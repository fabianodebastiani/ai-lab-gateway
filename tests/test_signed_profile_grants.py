"""Pure offline Stage-5 tests: synthetic Ed25519 keys, NO sudo/SSH/root changes."""
import base64
import json
from pathlib import Path
import importlib.util
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MODULE = Path(__file__).resolve().parents[1] / 'src/ai_lab_gateway/signed_profile_grants.py'
spec = importlib.util.spec_from_file_location('test_signed_profile_grants_impl', MODULE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

DEVICE = 'ai-lab-experiments-01-fd3dab34'
SUBJECT = 'auth0|synthetic-subject'
NOW = 100_000


@pytest.fixture
def signer():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public


def claim(mode='partial', **updates):
    c = {
        'version': m.VERSION, 'device_id': DEVICE,
        'subject': 'auth0|synthetic-subject', 'approved_by': 'auth0|human-approver',
        'approval_method': 'separate_human_root_console',
        'mode': mode, 'issued_at': NOW,
        'expires_at': NOW + 900 if mode == 'partial' else None,
        'generation': 1, 'grant_id': 'a' * 64,
        'capabilities': ['root-identity-check'] if mode == 'partial' else [],
    }
    c.update(updates)
    return c


def signed(c, private):
    signature = private.sign(m.canonical_grant_bytes(c))
    return json.dumps({'grant': c, 'signature': base64.b64encode(signature).decode()}).encode()


def verify(c, signer, *, now=NOW, expected_device=DEVICE):
    return m.verify_signed_grant(signed(c, signer[0]), trusted_public_key=signer[1],
                                 expected_device=expected_device, expected_subject=SUBJECT, now=now)


def effective(g, *, now=NOW, floor=NOW, epoch=0, revoked=()):
    return m.assess_signed_profile(g, now=now, trusted_time_floor=floor,
                                   revoked_generation=epoch, revoked_grant_ids=revoked)


def test_valid_lab_partial_metadata_is_not_sudo(signer):
    g = verify(claim(), signer)
    r = effective(g)
    assert r.effective_mode == 'partial'
    assert r.reason == 'signed_partial_metadata_only'
    assert r.capabilities == ('root-identity-check',)
    assert not hasattr(r, 'execute')


@pytest.mark.parametrize('duration', [900, 1800, 3600, 7200, 14400, 28800, 86400])
def test_all_partial_duration_options(signer, duration):
    g = verify(claim(expires_at=NOW + duration), signer)
    assert effective(g, now=NOW + duration - 1, floor=NOW).effective_mode == 'partial'
    assert effective(g, now=NOW + duration, floor=NOW).reason == 'expired'


@pytest.mark.parametrize('update', [
    {'device_id': 'raspberry-lab'}, {'mode': 'arbitrary'},
    {'expires_at': NOW + 901}, {'expires_at': NOW},
    {'expires_at': NOW + 86401}, {'issued_at': NOW + 31},
    {'issued_at': True}, {'expires_at': True},
    {'generation': True}, {'generation': -1}, {'generation': 0},
    {'grant_id': '../' * 20}, {'subject': ''}, {'approved_by': '\n'},
    {'approval_method': 'model_approval'},
    {'approval_method': ['separate_human_root_console']},
    {'capabilities': ['/bin/bash']},
    {'capabilities': ['root-identity-check', 'root-identity-check']},
    {'version': 'ai-lab-privexec-one-v1'},
])
def test_fail_closed_on_invalid_partial_claim(signer, update):
    with pytest.raises((ValueError, PermissionError)):
        verify(claim(**update), signer)


def test_tampering_invalidates_signature(signer):
    raw = json.loads(signed(claim(), signer[0]))
    raw['grant']['approved_by'] = 'auth0|attacker'
    with pytest.raises(PermissionError, match='signature'):
        m.verify_signed_grant(json.dumps(raw).encode(), trusted_public_key=signer[1],
                              expected_device=DEVICE, expected_subject=SUBJECT, now=NOW)


def test_other_key_is_not_trusted(signer):
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(PermissionError, match='signature'):
        m.verify_signed_grant(signed(claim(), signer[0]), trusted_public_key=other,
                              expected_device=DEVICE, expected_subject=SUBJECT, now=NOW)


def test_wrong_device_even_with_valid_issuer_signature(signer):
    with pytest.raises(PermissionError, match='unbound'):
        verify(claim(), signer, expected_device='windows-wsl')


def test_expiration_even_if_gateway_is_offline(signer):
    g = verify(claim(), signer)
    assert effective(g, now=NOW + 900, floor=NOW).effective_mode == 'restricted'


def test_local_revoke_by_epoch_or_grant_id(signer):
    g = verify(claim(), signer)
    assert effective(g, epoch=1).reason == 'revoked'
    assert effective(g, revoked=(g.grant_id,)).reason == 'revoked'
    assert effective(g, epoch=0).effective_mode == 'partial'


def test_clock_rollback_fails_closed(signer):
    g = verify(claim(), signer)
    with pytest.raises(PermissionError, match='clock'):
        effective(g, now=NOW - 1, floor=NOW)


def test_missing_or_malformed_root_state_denied(signer):
    g = verify(claim(), signer)
    for state in ({'trusted_time_floor': None}, {'revoked_generation': None},
                  {'trusted_time_floor': -1}, {'revoked_generation': True}):
        kwargs = dict(now=NOW, trusted_time_floor=NOW, revoked_generation=0,
                      revoked_grant_ids=())
        kwargs.update(state)
        with pytest.raises(PermissionError):
            m.assess_signed_profile(g, **kwargs)


def test_signed_unrestricted_is_still_disabled_offline(signer):
    g = verify(claim('unrestricted'), signer)
    result = effective(g)
    assert result.effective_mode == 'restricted'
    assert result.reason == 'unrestricted_not_enabled_in_lab'


def test_restricted_never_elevates(signer):
    g = verify(claim('restricted'), signer)
    assert effective(g).effective_mode == 'restricted'


@pytest.mark.parametrize('mode', ['unrestricted', 'restricted'])
def test_other_modes_reject_capabilities_or_duration(signer, mode):
    with pytest.raises(PermissionError):
        verify(claim(mode, capabilities=['root-identity-check']), signer)
    with pytest.raises(PermissionError):
        verify(claim(mode, expires_at=NOW + 900), signer)


def test_duplicate_keys_rejected(signer):
    raw = signed(claim(), signer[0]).decode()
    raw = raw[:-1] + ',"grant":{}}'
    with pytest.raises(ValueError, match='duplicate'):
        m.verify_signed_grant(raw.encode(), trusted_public_key=signer[1],
                              expected_device=DEVICE, expected_subject=SUBJECT, now=NOW)


def test_excessive_and_missing_bytes_rejected(signer):
    for raw in (b'', b'x' * 4097, b'{}'):
        with pytest.raises(ValueError):
            m.verify_signed_grant(raw, trusted_public_key=signer[1],
                                  expected_device=DEVICE, expected_subject=SUBJECT, now=NOW)


def test_unrecognized_and_extra_fields_rejected(signer):
    with pytest.raises(ValueError, match='fields'):
        verify(claim(unexpected='root'), signer)


def test_signature_domain_separates_one_use_permit(signer):
    c = claim()
    wrong_context = b'AI-LAB-PRIVEXEC-ONE-V1\x00' + m.canonical_grant_bytes(c)[len(m.DOMAIN):]
    s = signer[0].sign(wrong_context)
    raw = json.dumps({'grant': c, 'signature': base64.b64encode(s).decode()}).encode()
    with pytest.raises(PermissionError, match='signature'):
        m.verify_signed_grant(raw, trusted_public_key=signer[1],
                              expected_device=DEVICE, expected_subject=SUBJECT, now=NOW)


def test_revocation_state_must_be_explicitly_provided(signer):
    g = verify(claim(), signer)
    with pytest.raises(PermissionError):
        effective(g, revoked=None)


def test_nonfinite_json_is_rejected(signer):
    raw = signed(claim(), signer[0]).replace(b'100000', b'NaN', 1)
    with pytest.raises(ValueError):
        m.verify_signed_grant(raw, trusted_public_key=signer[1],
                              expected_device=DEVICE, expected_subject=SUBJECT, now=NOW)


def test_issuer_signed_grant_for_other_subject_rejected(signer):
    with pytest.raises(PermissionError, match='unbound'):
        verify(claim(subject='auth0|different-operator'), signer)
