import json

from ai_lab_gateway.audit import AuditEvent, JsonlAuditLog


def test_jsonl_audit_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    log.append(AuditEvent(
        subject="user-1",
        device_id="pi",
        action="status",
        success=True,
        duration_ms=12,
        exit_code=0,
    ))

    record = json.loads(path.read_text().strip())
    assert record["subject"] == "user-1"
    assert record["device_id"] == "pi"
    assert record["success"] is True
    assert "timestamp_utc" in record
