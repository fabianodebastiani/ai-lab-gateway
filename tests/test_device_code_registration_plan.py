"""Pure registration plan tests. No root access, network or file writes."""
import copy

import pytest

from ai_lab_gateway.device_code_registration_plan import (
    plan_restricted_wsl_registration, PERMITTED_ACTIONS
)
from ai_lab_gateway.registry import Device


@pytest.fixture
def state():
    registry = {"devices": [
        {"id": "raspberry-lab", "name": "Raspberry",
         "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
         "tunnel_port": 10001, "identity_file": "/keys/pi"},
        {"id": "windows-wsl", "name": "Existing WSL",
         "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
         "tunnel_port": 10002, "identity_file": "/keys/wsl"},
    ]}
    policy = {"users": [
        {"subject": "auth0|owner", "devices": {
            "windows-wsl": ["status", "exec"],
            "raspberry-lab": ["status"]}},
        {"subject": "auth0|visitor", "devices": {
            "raspberry-lab": ["status"]}},
    ]}
    identity = {
        "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX",
        "device_id": "laptop-5rjj0kbm-8210ee98",
        "device_name": "LAPTOP-5RJJ0KBM",
        "operator_subject": "auth0|owner",
        "access_mode": "restricted",
        "persistent": False, "reverse_listen_port": 10003,
    }
    return registry, policy, identity


def test_plan_preserves_originals_and_grants_only_verified_operator(state):
    registry, policy, identity = state
    previous = copy.deepcopy(state)
    new_registry, new_policy = plan_restricted_wsl_registration(
        protected_registry=registry, protected_policy=policy,
        approved_identity=identity)
    assert state == previous  # immutable inputs
    assert new_registry["devices"][:2] == registry["devices"]
    new_device = Device.from_dict(new_registry["devices"][-1])
    assert new_device.id == identity["device_id"]
    assert new_device.ssh_user == "ai-gateway"
    assert new_device.tunnel_host == "127.0.0.1"
    assert new_device.tunnel_port == 10003
    assert new_device.identity_file == (
        "/etc/ai-lab-gateway/device-code-keys/wsl-10003/identity")
    assert new_policy["users"][0]["devices"][identity["device_id"]] == list(
        PERMITTED_ACTIONS)
    assert identity["device_id"] not in new_policy["users"][1]["devices"]
    assert new_policy["users"][1] == policy["users"][1]
    assert new_policy["users"][0]["devices"]["windows-wsl"] == ["status", "exec"]


@pytest.mark.parametrize("changes", [
    {"device_id": "oracle-experiments"},
    {"reverse_listen_port": 10002},
    {"reverse_listen_port": 10004},
    {"reverse_listen_port": True},
    {"access_mode": "partial"},
    {"access_mode": "unrestricted"},
    {"persistent": True},
    {"operator_subject": "auth0|unrecognized"},
    {"operator_subject": ""},
    {"request_id": "invalid"},
    {"device_name": ""},
    {"ssh_user": "root"},
    {"identity_file": "/etc/shadow"},
    {"sudo": True},
])
def test_no_unapproved_id_port_owner_access_or_extra_fields(state, changes):
    registry, policy, identity = state
    with pytest.raises(PermissionError):
        plan_restricted_wsl_registration(
            protected_registry=registry,
            protected_policy=policy,
            approved_identity=dict(identity, **changes))


def test_duplicate_device_port_and_permissions_are_denied(state):
    registry, policy, identity = state
    for overlap in [
        {"id": identity["device_id"], "tunnel_port": 11000},
        {"id": "another", "tunnel_port": 10003},
    ]:
        bad = copy.deepcopy(registry)
        bad["devices"].append(overlap)
        with pytest.raises(PermissionError):
            plan_restricted_wsl_registration(
                protected_registry=bad,
                protected_policy=policy,
                approved_identity=identity)
    bad_acl = copy.deepcopy(policy)
    bad_acl["users"][0]["devices"][identity["device_id"]] = ["status"]
    with pytest.raises(PermissionError):
        plan_restricted_wsl_registration(
            protected_registry=registry,
            protected_policy=bad_acl,
            approved_identity=identity)


def test_existing_wsl_cannot_be_reassigned(state):
    registry, policy, identity = state
    bad = copy.deepcopy(registry)
    bad["devices"] = [
        record for record in bad["devices"] if record["id"] != "windows-wsl"]
    with pytest.raises(PermissionError):
        plan_restricted_wsl_registration(
            protected_registry=bad, protected_policy=policy,
            approved_identity=identity)


def test_auth0_subject_collision_is_denied(state):
    registry, policy, identity = state
    bad = copy.deepcopy(policy)
    bad["users"].append(copy.deepcopy(bad["users"][0]))
    with pytest.raises(PermissionError):
        plan_restricted_wsl_registration(
            protected_registry=registry, protected_policy=bad,
            approved_identity=identity)
