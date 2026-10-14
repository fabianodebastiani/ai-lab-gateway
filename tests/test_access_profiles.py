"""Regression tests for device access radio controls and time limits."""
import importlib.util
import sys
from pathlib import Path
import pytest

@pytest.fixture
def access():
    path = Path(__file__).resolve().parents[1] / "src/ai_lab_gateway/access_profiles.py"
    spec = importlib.util.spec_from_file_location("profiles_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def test_exactly_three_modes(access):
    assert [m.value for m in access.AccessMode] == ["restricted", "partial", "unrestricted"]
    assert access.DEFAULT_SELECTION.mode is access.AccessMode.RESTRICTED

@pytest.mark.parametrize("ttl", [900, 1800, 3600, 7200, 14400, 28800, 86400])
def test_partial_dropdown(access, ttl):
    selected = access.AccessSelection.validate("partial", ttl)
    g = access.AccessGrant.issue("raspberry-lab", "authorized-subject", selected,
                                 explicit_confirmation=True, now=1000)
    assert g.administrative_access(now=1000 + ttl - 1)
    assert not g.administrative_access(now=1000 + ttl)

@pytest.mark.parametrize("ttl", [None, 0, 1, 360.0, True, 86401])
def test_partial_rejects_invalid_duration(access, ttl):
    with pytest.raises(ValueError):
        access.AccessSelection.validate("partial", ttl)

@pytest.mark.parametrize("mode", ["restricted", "unrestricted"])
def test_no_duration_for_other_modes(access, mode):
    assert access.AccessSelection.validate(mode).duration_seconds is None
    with pytest.raises(ValueError):
        access.AccessSelection.validate(mode, 1800)

def test_all_profiles_require_explicit_confirmation(access):
    for mode in access.AccessMode:
        ttl = 1800 if mode is access.AccessMode.PARTIAL else None
        choice = access.AccessSelection.validate(mode, ttl)
        with pytest.raises(PermissionError):
            access.AccessGrant.issue("raspberry-lab", "subject", choice,
                                     explicit_confirmation=False, now=1000)

def test_restricted_never_allows_admin(access):
    g = access.AccessGrant.issue("raspberry-lab", "subject",
                                 access.AccessSelection.validate("restricted"),
                                 explicit_confirmation=True, now=1000)
    assert not g.administrative_access(now=1000)

def test_unrestricted_requires_explicit_choice(access):
    g = access.AccessGrant.issue("raspberry-lab", "subject",
                                 access.AccessSelection.validate("unrestricted"),
                                 explicit_confirmation=True, now=1000)
    assert g.administrative_access(now=999999)

def test_invalid_device_id_rejected(access):
    with pytest.raises(ValueError):
        access.AccessGrant.issue("../etc", "subject",
                                 access.DEFAULT_SELECTION,
                                 explicit_confirmation=True, now=1000)
