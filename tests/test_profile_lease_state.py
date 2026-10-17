"""Disposable synthetic Stage-5 root state and short-lease tests.

Root-only tests run on a disposable GitHub runner, never managed devices.
"""
import base64
import json
import os
from pathlib import Path
import stat
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from ai_lab_gateway import profile_lease_state as m

DEVICE = 'ai-lab-experiments-01-fd3dab34'
SUBJECT = 'auth0|synthetic-subject'
BOOT_A = '11111111-2222-3333-4444-555555555555'
BOOT_B = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
NOW = 100_000


@pytest.fixture
def signer():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


@pytest.fixture
def grant():
    return m.VerifiedProfileGrant(
        device_id=DEVICE, subject=SUBJECT, approved_by='auth0|human',
        approval_method='separate_human_root_console', mode='partial',
        issued_at=NOW, expires_at=NOW+900, generation=1,
        grant_id='a'*64, capabilities=(m.CAPABILITY,),
    )


def lease_claim(grant, **changes):
    data = dict(
        version=m.LEASE_VERSION, device_id=grant.device_id,
        subject=grant.subject, grant_id=grant.grant_id,
        generation=grant.generation, mode='partial',
        capability=m.CAPABILITY, boot_id=BOOT_A,
        issued_at=NOW, expires_at=NOW+300, lease_id='b'*64,
    )
    data.update(changes)
    return data


def encode(claim, signer):
    sig = signer[0].sign(m.canonical_lease_bytes(claim))
    return json.dumps({'lease':claim,'signature':base64.b64encode(sig).decode()}).encode()


def check(c, signer, grant, now=NOW, boot=BOOT_A):
    return m.verify_short_lease(
        encode(c, signer), trusted_public_key=signer[1],
        grant=grant, expected_boot_id=boot, now=now,
    )


def test_short_lease_valid_boundary_and_signature(signer, grant):
    v = check(lease_claim(grant), signer, grant)
    assert v.expires_at-NOW == 300
    assert v.grant_id == grant.grant_id
    with pytest.raises(PermissionError):
        check(lease_claim(grant), signer, grant, now=NOW+300)


@pytest.mark.parametrize('change', [
    {'device_id':'raspberry-lab'}, {'subject':'auth0|other'},
    {'grant_id':'c'*64}, {'generation':2}, {'generation':True},
    {'mode':'unrestricted'}, {'capability':'shell'},
    {'boot_id':BOOT_B}, {'expires_at':NOW+301},
    {'issued_at':NOW-5,'expires_at':NOW+296},
    {'issued_at':NOW+31}, {'issued_at':True}, {'expires_at':True},
    {'expires_at':NOW}, {'expires_at':NOW+901},
    {'lease_id':'../etc'}, {'version':'old'},
])
def test_short_lease_rejects_unbound_or_invalid_claim(change, signer, grant):
    with pytest.raises((ValueError, PermissionError)):
        check(lease_claim(grant, **change), signer, grant)


def test_lease_expires_no_later_than_original_grant(signer, grant):
    with pytest.raises(PermissionError):
        check(lease_claim(grant, issued_at=NOW+800, expires_at=NOW+1100),
              signer, grant, now=NOW+800)


def test_restrict_mode_cannot_obtain_partial_lease(signer, grant):
    from dataclasses import replace
    with pytest.raises(PermissionError):
        check(lease_claim(grant), signer, replace(grant,mode='unrestricted'))


def test_wrong_issuer_or_tampered_claim(signer, grant):
    raw = json.loads(encode(lease_claim(grant), signer))
    raw['lease']['expires_at'] = NOW+1
    with pytest.raises(PermissionError, match='signature'):
        m.verify_short_lease(
            json.dumps(raw).encode(), trusted_public_key=signer[1],
            grant=grant, expected_boot_id=BOOT_A, now=NOW,
        )
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(PermissionError, match='signature'):
        m.verify_short_lease(
            encode(lease_claim(grant), signer), trusted_public_key=other,
            grant=grant, expected_boot_id=BOOT_A, now=NOW,
        )


def test_replay_within_same_boot_is_lease_not_one_use(signer, grant):
    # A lease may be reused during 300s; a privileged command still requires
    # the separate signed, exact-argv, one-use executor. This code NEVER runs it.
    p = lease_claim(grant)
    assert check(p, signer, grant).lease_id == check(p, signer, grant, now=NOW+1).lease_id


def test_wrong_boot_refuses_leases(signer, grant):
    with pytest.raises(PermissionError):
        check(lease_claim(grant), signer, grant, boot=BOOT_B)


def test_duplicate_lease_keys_and_oversize(signer, grant):
    packet = encode(lease_claim(grant), signer).decode()
    for invalid in (packet[:-1]+',"lease":{}}', 'x'*4097, '', '{}'):
        with pytest.raises((ValueError, PermissionError)):
            m.verify_short_lease(invalid.encode(),trusted_public_key=signer[1],
                                 grant=grant,expected_boot_id=BOOT_A,now=NOW)


@pytest.fixture
def root_store(tmp_path):
    if os.geteuid()!=0:
        pytest.skip('root-only synthetic CI tests')
    directory = tmp_path/'root-profile-state'
    directory.mkdir(mode=0o700)
    clock = [NOW]
    boot = [BOOT_A]
    store = m.RootProfileState(
        directory, DEVICE, clock=lambda:clock[0], boot_reader=lambda:boot[0])
    store.initialize()
    return store, clock, boot


def test_initialize_root_ownership_and_fsync_layout(root_store):
    store,_,_ = root_store
    for name in ('lock','state.json'):
        p=store.directory/name
        assert stat.S_IMODE(p.stat().st_mode)==0o600
        assert p.stat().st_uid==0
    with pytest.raises(PermissionError):
        store.initialize()


def test_local_state_revoke_id_is_persistent(root_store):
    store,clock,_ = root_store
    store.revoke_id('a'*64)
    state=m._read_state(store.directory/'state.json',DEVICE)
    assert state['revoked_grant_ids']==['a'*64]
    reopened=m.RootProfileState(store.directory,DEVICE,
                 clock=lambda:clock[0],boot_reader=lambda:BOOT_A)
    reopened.revoke_id('a'*64)
    assert m._read_state(store.directory/'state.json',DEVICE)['revoked_grant_ids']==['a'*64]


def test_local_generation_revocation_monotonic(root_store):
    store,_,_ = root_store
    store.revoke_through_generation(3)
    store.revoke_through_generation(1)
    assert m._read_state(store.directory/'state.json',DEVICE)['revoked_generation']==3


def test_time_watermark_persists_across_calls(root_store):
    store,clock,_ = root_store
    clock[0]=NOW+10
    store.revoke_through_generation(1)
    assert m._read_state(store.directory/'state.json',DEVICE)['time_floor']==NOW+10
    clock[0]=NOW+9
    with pytest.raises(PermissionError,match='clock rollback'):
        store.revoke_through_generation(2)
    assert m._read_state(store.directory/'state.json',DEVICE)['revoked_generation']==1


def test_reboot_fail_closed(root_store):
    store,_,boot=root_store
    boot[0]=BOOT_B
    with pytest.raises(PermissionError,match='boot changed'):
        store.revoke_through_generation(2)


def test_root_state_symlink_rejected(root_store):
    store,_,_=root_store
    protected=store.directory/'state.json'
    protected.rename(store.directory/'real')
    protected.symlink_to(store.directory/'real')
    with pytest.raises(OSError):
        store.revoke_through_generation(2)


def test_root_state_writable_or_nonroot_rejected(root_store, monkeypatch):
    store,_,_=root_store
    state=store.directory/'state.json'
    state.chmod(0o666)
    with pytest.raises(PermissionError):
        store.revoke_id('d'*64)
    state.chmod(0o600)
    monkeypatch.setattr(m.os,'geteuid',lambda:1000)
    with pytest.raises(PermissionError,match='root-only'):
        store.revoke_id('d'*64)


def test_root_state_malformed_json_fails_closed(root_store):
    store,_,_=root_store
    p=store.directory/'state.json'
    p.write_text('{"invalid":true}')
    with pytest.raises(PermissionError,match='malformed'):
        store.revoke_id('d'*64)


def test_root_state_missing_file_fails_closed(root_store):
    store,_,_=root_store
    (store.directory/'state.json').unlink()
    with pytest.raises(OSError):
        store.revoke_id('c'*64)


def test_root_state_bounded_revocation_list(root_store):
    store,_,_=root_store
    for x in range(m.MAX_REVOKED_IDS):
        store.revoke_id(f'{x:064x}')
    with pytest.raises(PermissionError,match='list full'):
        store.revoke_id('f'*64)
    assert len(m._read_state(store.directory/'state.json',DEVICE)['revoked_grant_ids'])==m.MAX_REVOKED_IDS


def test_invalid_revocation_input_rejected(root_store):
    store,_,_=root_store
    for x in (True,-1,2**64,3.5):
        with pytest.raises(ValueError):
            store.revoke_through_generation(x)
    with pytest.raises(ValueError):
        store.revoke_id('../etc')


def test_signed_metadata_without_lease_denied(root_store, monkeypatch, grant, signer):
    store,_,_=root_store
    monkeypatch.setattr(m,'verify_signed_grant',lambda *args,**kwargs:grant)
    with pytest.raises((PermissionError,ValueError)):
        store.evaluate_signed(
            b'synthetic grant',b'',trusted_public_key=signer[1],
            expected_subject=SUBJECT,
        )


def test_signed_metadata_with_fresh_lease_and_revoke(root_store, monkeypatch, grant, signer):
    store,clock,_=root_store
    monkeypatch.setattr(m,'verify_signed_grant',lambda *args,**kwargs:grant)
    raw=encode(lease_claim(grant),signer)
    x=store.evaluate_signed(b'synthetic grant',raw,trusted_public_key=signer[1],
                            expected_subject=SUBJECT)
    assert x.effective_mode=='partial' and x.reason=='signed_lease_metadata_only'
    assert not hasattr(x,'execute')
    store.revoke_id(grant.grant_id)
    assert store.evaluate_signed(b'synthetic grant',raw,trusted_public_key=signer[1],
                   expected_subject=SUBJECT).effective_mode=='restricted'


def test_revoke_generation_even_for_valid_signed_lease(root_store, monkeypatch, grant, signer):
    store,_,_=root_store
    monkeypatch.setattr(m,'verify_signed_grant',lambda *args,**kwargs:grant)
    raw=encode(lease_claim(grant),signer)
    store.revoke_through_generation(grant.generation)
    assert store.evaluate_signed(b'synthetic',raw,trusted_public_key=signer[1],
                    expected_subject=SUBJECT).reason=='revoked'


def test_clock_goes_backward_deny_signed_lease(root_store, monkeypatch, grant, signer):
    store,clock,_=root_store
    monkeypatch.setattr(m,'verify_signed_grant',lambda *args,**kwargs:grant)
    clock[0]=NOW+50
    raw=encode(lease_claim(grant,issued_at=NOW+50,expires_at=NOW+300),signer)
    assert store.evaluate_signed(b'synthetic',raw,trusted_public_key=signer[1],
                                 expected_subject=SUBJECT).effective_mode=='partial'
    clock[0]=NOW+40
    with pytest.raises(PermissionError,match='clock rollback'):
        store.evaluate_signed(b'synthetic',raw,trusted_public_key=signer[1],
                              expected_subject=SUBJECT)


def test_short_lease_ttl_enforced_without_prior_revocation(root_store, monkeypatch, grant, signer):
    store,clock,_=root_store
    monkeypatch.setattr(m,'verify_signed_grant',lambda *args,**kwargs:grant)
    raw=encode(lease_claim(grant),signer)
    assert store.evaluate_signed(b'synthetic',raw,trusted_public_key=signer[1],
                                 expected_subject=SUBJECT).effective_mode=='partial'
    clock[0]=NOW+300
    with pytest.raises(PermissionError,match='expired'):
        store.evaluate_signed(b'synthetic',raw,trusted_public_key=signer[1],
                              expected_subject=SUBJECT)


def test_parallel_revocations_do_not_drop_updates(root_store):
    import multiprocessing
    store,_,_=root_store
    def revoke(x):
        p=m.RootProfileState(store.directory,DEVICE,clock=lambda:NOW,boot_reader=lambda:BOOT_A)
        p.revoke_id(f'{x:064x}')
    ctx=multiprocessing.get_context('fork')
    workers=[ctx.Process(target=revoke,args=(x,)) for x in range(8)]
    for w in workers: w.start()
    for w in workers:
        w.join(timeout=10)
        assert w.exitcode==0
    ids=m._read_state(store.directory/'state.json',DEVICE)['revoked_grant_ids']
    assert len(ids)==8


def _real_signed_grant(signer, *, subject=SUBJECT):
    """Synthetic full signed profile envelope, WITHOUT monkeypatching the verifier."""
    from ai_lab_gateway import signed_profile_grants as g
    claim = {
        'version': g.VERSION, 'device_id': DEVICE,
        'subject': subject, 'approved_by': 'auth0|human',
        'approval_method': 'separate_human_root_console',
        'mode': 'partial', 'issued_at': NOW, 'expires_at': NOW+900,
        'generation': 1, 'grant_id': 'a'*64,
        'capabilities': [m.CAPABILITY],
    }
    signature = signer[0].sign(g.canonical_grant_bytes(claim))
    return json.dumps({'grant':claim,
                       'signature':base64.b64encode(signature).decode()}).encode()


def test_full_two_signature_chain_and_local_revoke(root_store, signer, grant):
    store,_,_ = root_store
    raw_grant = _real_signed_grant(signer)
    raw_lease = encode(lease_claim(grant), signer)
    result = store.evaluate_signed(raw_grant, raw_lease,
                                   trusted_public_key=signer[1],
                                   expected_subject=SUBJECT)
    assert result.effective_mode == 'partial'
    assert result.reason == 'signed_lease_metadata_only'
    store.revoke_id(grant.grant_id)
    result = store.evaluate_signed(raw_grant, raw_lease,
                                   trusted_public_key=signer[1],
                                   expected_subject=SUBJECT)
    assert result.effective_mode == 'restricted'


def test_full_chain_rejects_wrong_subject_and_tampering(root_store, signer, grant):
    store,_,_ = root_store
    lease = encode(lease_claim(grant), signer)
    with pytest.raises(PermissionError):
        store.evaluate_signed(_real_signed_grant(signer, subject='auth0|other'),
                              lease, trusted_public_key=signer[1],
                              expected_subject=SUBJECT)
    tampered = json.loads(_real_signed_grant(signer))
    tampered['grant']['expires_at'] = NOW+1800
    with pytest.raises(PermissionError):
        store.evaluate_signed(json.dumps(tampered).encode(), lease,
                              trusted_public_key=signer[1],
                              expected_subject=SUBJECT)
