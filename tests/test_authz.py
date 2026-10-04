import json

import pytest

from ai_lab_gateway.authz import AuthorizationPolicy, Principal


def test_explicit_device_action_grant(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"users": [{
        "subject": "user-1",
        "devices": {"pi": ["status", "exec"]}
    }]}))

    policy = AuthorizationPolicy.load(path)
    principal = Principal("user-1")

    assert policy.allows(principal, "pi", "exec")
    assert not policy.allows(principal, "pi", "write_file")
    assert not policy.allows(principal, "other", "exec")


def test_require_denies_by_default(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"users": []}))
    policy = AuthorizationPolicy.load(path)

    with pytest.raises(PermissionError):
        policy.require(Principal("unknown"), "pi", "exec")
