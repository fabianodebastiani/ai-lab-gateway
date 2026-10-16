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


def test_pending_request_quota(broker):
    requests = [new_request(broker) for _ in range(broker.MAX_PENDING_PER_SUBJECT)]
    assert all(request["ok"] for request in requests)
    assert new_request(broker)["error"] == "pending_quota_reached"
    rid = requests[0]["request_id"]
    assert broker.dispatch({"action": "revoke", "subject": "auth0|user-A",
                            "request_id": rid})["status"] == "revoked"
    assert new_request(broker)["ok"] is True


def test_rejects_nonstr_operation(broker):
    assert new_request(broker, operation=["gateway-service-status"])["error"] == "invalid_parameters"


def test_fixed_root_write_is_not_available_until_approval(broker, monkeypatch):
    observed = []
    def fake_run(argv, **kwargs):
        observed.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(broker.subprocess, "run", fake_run)
    rid = new_request(broker, operation="broker-root-write-selftest")["request_id"]
    assert execute(broker, rid)["error"] == "not_approved"
    assert observed == []
    assert broker.admin("approve", rid) == 0
    assert execute(broker, rid)["ok"] is True
    assert observed == [("/usr/bin/touch",
                         "/var/lib/ai-lab-privilege-broker/root-write-selftest.ok")]
    assert execute(broker, rid)["error"] == "not_approved"


def test_web_approval_api_requires_pending_and_is_one_use(broker):
    rid = new_request(broker)["request_id"]
    listed = broker.approval_dispatch({"action": "list"})
    assert listed["ok"] is True
    assert any(item["request_id"] == rid for item in listed["requests"])
    assert execute(broker, rid)["error"] == "not_approved"
    assert broker.approval_dispatch({"action": "approve", "request_id": rid})["status"] == "approved"
    assert execute(broker, rid)["ok"] is True
    assert execute(broker, rid)["error"] == "not_approved"
    assert broker.approval_dispatch({"action": "approve", "request_id": rid})["error"] == "not_pending"


def test_web_approval_deny_and_invalid_actions(broker):
    rid = new_request(broker)["request_id"]
    assert broker.approval_dispatch({"action": "shell"})["error"] == "unsupported"
    assert broker.approval_dispatch({"action": "deny", "request_id": rid})["status"] == "denied"
    assert execute(broker, rid)["error"] == "not_approved"
    assert broker.approval_dispatch({"action": "approve", "request_id": rid})["error"] == "not_pending"
    assert broker.approval_dispatch({"action": "approve", "request_id": ["bad"]})["error"] == "invalid_request_id"


def test_web_approval_pending_expiry(broker, monkeypatch):
    t = [2_000_000]
    monkeypatch.setattr(broker.time, "time", lambda: t[0])
    rid = new_request(broker)["request_id"]
    t[0] += broker.PENDING_TTL + 1
    assert broker.approval_dispatch({"action": "approve", "request_id": rid})["error"] == "not_pending"
    assert not broker.approval_dispatch({"action": "list"})["requests"]


def test_pairing_service_journal_is_read_only_and_requires_human_approval(broker, monkeypatch):
    """MCP must never be able to provide shell text to this privileged operation."""
    seen = []
    def runner(argv, **kwargs):
        seen.append((tuple(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, "pairing-error\\n", "")
    monkeypatch.setattr(broker.subprocess, "run", runner)
    requested = new_request(broker, operation="pairing-service-journal", ttl=300)
    assert requested["ok"] and requested["status"] == "pending"
    rid = requested["request_id"]
    assert execute(broker, rid)["error"] == "not_approved"
    assert seen == []
    assert broker.approval_dispatch({"action": "approve", "request_id": rid})["status"] == "approved"
    reply = execute(broker, rid)
    assert reply["ok"] and reply["stdout"] == "pairing-error\\n"
    assert seen == [
        (("/usr/bin/journalctl", "--unit=ai-lab-pairing.service",
          "--no-pager", "--lines=60", "--output=short-iso"),
         {"shell": False, "capture_output": True, "text": True, "timeout": 15})
    ]
    assert execute(broker, rid)["error"] == "not_approved"
    assert new_request(broker, operation="pairing-service-journal;sh")["error"] == "invalid_parameters"


def test_oracle_ssh_protected_paths_needs_independent_approval(broker, monkeypatch):
    """No caller-supplied command or pathname can reach root stat."""
    invocations = []

    def capture(argv, **kwargs):
        invocations.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, "fixed metadata only\\n", "")

    monkeypatch.setattr(broker.subprocess, "run", capture)
    request = new_request(
        broker, operation="oracle-ssh-protected-paths", ttl=300)
    assert request["ok"] is True
    request_id = request["request_id"]

    denied = broker.dispatch({
        "action": "execute", "subject": "auth0|user-A",
        "request_id": request_id,
        "command": "/usr/bin/bash", "args": ["-c", "id"],
    })
    assert denied["ok"] is False and denied["error"] == "not_approved"
    assert invocations == []

    # This is the same authenticated independent-approver RPC used by the
    # password + TOTP website after it has validated the human decision.
    approved = broker.approval_dispatch({
        "action": "approve", "request_id": request_id})
    assert approved["ok"] is True
    assert approved["status"] == "approved"

    done = broker.dispatch({
        "action": "execute", "subject": "auth0|user-A",
        "request_id": request_id,
        "command": "/usr/bin/bash",
        "path": "/etc/shadow",
    })
    assert done["ok"] is True
    assert done["status"] == "consumed"
    assert len(invocations) == 1
    assert invocations[0] == broker.OPERATIONS["oracle-ssh-protected-paths"]
    assert invocations[0][0] == "/usr/bin/stat"
    assert "shell" not in done
    assert broker.dispatch({
        "action": "execute", "subject": "auth0|user-A",
        "request_id": request_id})["error"] == "not_approved"


def test_oracle_ssh_protected_paths_cannot_be_approved_by_operational_actor(broker):
    """A model-controlled request payload cannot bypass approver step."""
    req = new_request(broker, operation="oracle-ssh-protected-paths")
    assert req["ok"] is True
    rid = req["request_id"]
    result = broker.dispatch({
        "action": "approve", "subject": "auth0|user-A",
        "request_id": rid, "approval": True,
    })
    assert result["ok"] is False
    assert broker.dispatch({
        "action": "execute", "subject": "auth0|user-A",
        "request_id": rid})["error"] == "not_approved"
