"""Unit tests for the independently approved Oracle privilege broker.

Run: python -m pytest tests/test_privilege_broker.py -q
The tests do not require root, Auth0 credentials, or a live daemon.
"""
import importlib.util
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def broker(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "scripts" / "privilege_broker_daemon.py"
    spec = importlib.util.spec_from_file_location("privilege_broker_under_test", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "DB", tmp_path / "requests.json")
    monkeypatch.setattr(module, "AUDIT", tmp_path / "requests-audit.jsonl")
    monkeypatch.setattr(module, "LOCK", tmp_path / "requests.lock")
    (tmp_path / "requests-audit.jsonl").touch()
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "active\n", ""),
    )
    return module


def new_request(broker, subject="auth0|user-A", operation="gateway-service-status", ttl=1800):
    return broker.dispatch({"action": "request", "subject": subject,
                            "operation": operation, "ttl_seconds": ttl})


def execute(broker, rid, subject="auth0|user-A"):
    return broker.dispatch({"action": "execute", "subject": subject, "request_id": rid})


def test_manual_approval_required_and_one_time(broker):
    req = new_request(broker)
    assert req["ok"] is True and req["status"] == "pending"
    rid = req["request_id"]
    assert execute(broker, rid)["error"] == "not_approved"
    assert broker.admin("approve", rid) == 0
    result = execute(broker, rid)
    assert result["ok"] and result["stdout"] == "active\n"
    assert execute(broker, rid)["error"] == "not_approved"


def test_subject_binding_and_revoke(broker):
    rid = new_request(broker)["request_id"]
    assert broker.admin("approve", rid) == 0
    assert execute(broker, rid, "auth0|user-B")["error"] == "not_found"
    revoked = broker.dispatch({"action": "revoke", "subject": "auth0|user-A",
                               "request_id": rid})
    assert revoked["status"] == "revoked"
    assert execute(broker, rid)["error"] == "not_approved"


def test_expiry_and_pending_deadline(broker, monkeypatch):
    now = [1_000_000]
    monkeypatch.setattr(broker.time, "time", lambda: now[0])
    rid = new_request(broker, ttl=1)["request_id"]
    assert broker.admin("approve", rid) == 0
    now[0] += 2
    assert execute(broker, rid)["error"] == "not_approved"
    rid2 = new_request(broker)["request_id"]
    now[0] += 3601
    assert broker.admin("approve", rid2) == 77


def test_invalid_operation_ttl_and_subject_denied(broker):
    assert new_request(broker, operation="shell")["error"] == "invalid_parameters"
    assert new_request(broker, ttl=86401)["error"] == "invalid_parameters"
    assert new_request(broker, subject="")["error"] == "invalid_subject"
    assert new_request(broker, ttl=True)["error"] == "invalid_parameters"


def test_concurrent_replay_only_one_can_win(broker):
    rid = new_request(broker)["request_id"]
    assert broker.admin("approve", rid) == 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: execute(broker, rid), range(8)))
    assert sum(result.get("ok", False) for result in results) == 1


def test_audit_records_approval_and_denial(broker):
    rid = new_request(broker)["request_id"]
    execute(broker, rid)
    broker.admin("approve", rid)
    log = broker.AUDIT.read_text()
    assert '"action":"request"' in log
    assert '"action":"execute"' in log
    assert '"action":"admin_approve"' in log
