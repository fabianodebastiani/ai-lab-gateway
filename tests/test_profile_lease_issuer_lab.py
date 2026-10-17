"""Stage 5 issuer laboratory: synthetic independent human and device signatures.

Run ONLY as root on disposable CI runner. NO Oracle/SSH/MCP/real approvals.
"""
import base64
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from ai_lab_gateway import profile_lease_issuer_lab as m
from ai_lab_gateway.signed_profile_grants import verify_signed_grant
from ai_lab_gateway.profile_lease_state import verify_short_lease

DEVICE = 'ai-lab-experiments-01-fd3dab34'
SUBJECT = 'auth0|synthetic-human'
BOOT = '11111111-2222-3333-4444-555555555555'
NOW = 100000


def public(private):
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture
def rig(tmp_path):
    if os.geteuid() != 0:
        pytest.skip('run issuer state tests only on a disposable root CI runner')
    issuer, human, device = (Ed25519PrivateKey.generate() for _ in range(3))
    directory = tmp_path / 'issuer'
    directory.mkdir(mode=0o700)
    app = m.ProfileLeaseIssuerLab(directory, issuer_key=issuer,
        human_approval_key=public(human), device_keys={DEVICE:public(device)})
    app.initialize(NOW)
    return app, human, device


def consent_packet(human, **changes):
    fields = {
        'version':m.APPROVAL_VERSION, 'decision_id':'a'*64, 'device_id':DEVICE,
        'subject':SUBJECT, 'approved_by':'auth0|independent-consenter',
        'approval_method':'separate_human_root_console', 'mode':'partial',
        'duration_seconds':900,'capabilities':[m.CAPABILITY],
        'decided_at':NOW,'expires_at':NOW+120,'confirmed':True,
    }
    fields.update(changes)
    return m._signed('consent',fields,human,m.APPROVAL_DOMAIN)


def approved_grant(rig, **changes):
    app,human,_=rig
    result=app.issue_approved_partial(consent_packet(human,**changes),
        expected_subject=SUBJECT, expected_device=DEVICE, now=NOW)
    claim=json.loads(result)['grant']
    return result,claim


def renewal_packet(device, grant, **changes):
    fields={
        'version':m.RENEWAL_VERSION, 'request_id':'b'*64, 'device_id':DEVICE,
        'subject':SUBJECT, 'grant_id':grant['grant_id'],
        'generation':grant['generation'], 'capability':m.CAPABILITY,
        'boot_id':BOOT, 'requested_at':NOW,
    }
    fields.update(changes)
    return m._signed('renewal',fields,device,m.RENEWAL_DOMAIN)


def renew(rig, grant_packet, claim, *, now=NOW, **changes):
    app,_,device=rig
    return app.renew_short_lease(grant_packet, renewal_packet(device,claim,**changes),
        expected_subject=SUBJECT, expected_device=DEVICE,now=now)


def test_success_grant_and_renewal_two_distinct_human_and_device_keys(rig):
    app,_,_=rig
    parent,claim=approved_grant(rig)
    grant=verify_signed_grant(parent,trusted_public_key=app.issuer_public,
        expected_device=DEVICE,expected_subject=SUBJECT,now=NOW)
    raw=renew(rig,parent,claim)
    result=verify_short_lease(raw,trusted_public_key=app.issuer_public,
        grant=grant,expected_boot_id=BOOT,now=NOW)
    assert result.expires_at-NOW==300
    assert result.capability=='root-identity-check'
    assert result.grant_id==grant.grant_id
    assert result.mode=='partial'


@pytest.mark.parametrize('bad', [
    {'confirmed':False},{'mode':'unrestricted'},
    {'capabilities':['/bin/bash']},{'duration_seconds':899},
    {'duration_seconds':True},{'device_id':'raspberry-lab'},
    {'subject':'auth0|other'},{'approved_by':''},
    {'expires_at':NOW-1},{'expires_at':NOW+121},
    {'decided_at':NOW+31},{'decision_id':'../etc'},
    {'approval_method':'chatgpt_text'},
])
def test_unsigned_or_noncompliant_human_approval_never_creates_grant(rig,bad):
    app,human,_=rig
    with pytest.raises((ValueError,PermissionError)):
        app.issue_approved_partial(consent_packet(human,**bad),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)
    assert app.db.exists()


def test_human_signature_cannot_be_forged_by_caller(rig):
    app,human,_=rig
    raw=json.loads(consent_packet(human))
    raw['consent']['duration_seconds']=86400
    with pytest.raises(PermissionError,match='signature'):
        app.issue_approved_partial(json.dumps(raw).encode(),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)
    rogue=Ed25519PrivateKey.generate()
    with pytest.raises(PermissionError,match='signature'):
        app.issue_approved_partial(consent_packet(rogue),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)


def test_independent_approval_signing_key_required(tmp_path):
    if os.geteuid()!=0: pytest.skip('root-only')
    signing=Ed25519PrivateKey.generate()
    with pytest.raises(ValueError,match='separate'):
        m.ProfileLeaseIssuerLab(tmp_path,issuer_key=signing,
            human_approval_key=public(signing),device_keys={DEVICE:public(Ed25519PrivateKey.generate())})


def test_duplicate_human_consent_cannot_issue_second_grant(rig):
    app,_,_=rig
    approved_grant(rig)
    with pytest.raises(Exception) as err:
        approved_grant(rig)
    assert 'UNIQUE' in str(err.value)


def test_valid_human_decision_replay_still_denied_after_db_reopen(rig):
    app,human,device=rig
    approved_grant(rig)
    again=m.ProfileLeaseIssuerLab(app.directory,issuer_key=app.issuer_key,
        human_approval_key=public(human),device_keys={DEVICE:public(device)})
    with pytest.raises(Exception):
        again.issue_approved_partial(consent_packet(human),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)


@pytest.mark.parametrize('bad', [
    {'device_id':'windows-wsl'},{'subject':'auth0|other'},
    {'grant_id':'f'*64},{'generation':True},
    {'generation':999},{'capability':'sudo-shell'},
    {'requested_at':NOW+31},{'requested_at':NOW-91},
    {'requested_at':True},{'request_id':'../../'},
])
def test_renewal_needs_fresh_correct_device_attestation(rig,bad):
    parent,claim=approved_grant(rig)
    with pytest.raises((ValueError,PermissionError)):
        renew(rig,parent,claim,**bad)


def test_no_lease_from_unsanctioned_device_key(rig):
    app,_,_=rig
    parent,claim=approved_grant(rig)
    bad=Ed25519PrivateKey.generate()
    with pytest.raises(PermissionError,match='signature'):
        app.renew_short_lease(parent,renewal_packet(bad,claim),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)


def test_no_lease_from_tampered_original_grant(rig):
    app,_,device=rig
    parent,claim=approved_grant(rig)
    changed=json.loads(parent)
    changed['grant']['expires_at']+=60
    with pytest.raises(PermissionError):
        app.renew_short_lease(json.dumps(changed).encode(),
            renewal_packet(device,claim), expected_subject=SUBJECT,
            expected_device=DEVICE,now=NOW)


def test_same_device_request_nonce_burned_once_even_when_process_restarts(rig):
    app,human,device=rig
    parent,claim=approved_grant(rig)
    packet=renewal_packet(device,claim)
    app.renew_short_lease(parent,packet,expected_subject=SUBJECT,
                          expected_device=DEVICE,now=NOW)
    again=m.ProfileLeaseIssuerLab(app.directory,issuer_key=app.issuer_key,
        human_approval_key=public(human),device_keys={DEVICE:public(device)})
    with pytest.raises(Exception) as err:
        again.renew_short_lease(parent,packet,
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)
    assert 'UNIQUE' in str(err.value)


def test_fresh_attestation_permits_a_new_renewal(rig):
    parent,claim=approved_grant(rig)
    first=json.loads(renew(rig,parent,claim))['lease']['lease_id']
    second=json.loads(renew(rig,parent,claim,request_id='c'*64,requested_at=NOW+10,
                            now=NOW+10))['lease']['lease_id']
    assert first != second


def test_parent_expiration_prevents_renewal(rig):
    parent,claim=approved_grant(rig)
    with pytest.raises(PermissionError):
        renew(rig,parent,claim,now=NOW+900,requested_at=NOW+900)


def test_lease_cannot_extend_beyond_parent(rig):
    app,human,_=rig
    parent=app.issue_approved_partial(consent_packet(human,duration_seconds=900),
        expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)
    claim=json.loads(parent)['grant']
    late=renew(rig,parent,claim,now=NOW+800,requested_at=NOW+800)
    assert json.loads(late)['lease']['expires_at']==NOW+900


def test_revoke_prevents_further_renewals(rig):
    app,_,_=rig
    parent,claim=approved_grant(rig)
    first=renew(rig,parent,claim)
    assert first
    app.revoke_grant(claim['grant_id'],now=NOW+1)
    with pytest.raises(PermissionError,match='revoked'):
        renew(rig,parent,claim,now=NOW+2,
              request_id='c'*64,requested_at=NOW+2)


def test_device_generation_revocation_blocks_renewal(rig):
    app,_,_=rig
    parent,claim=approved_grant(rig)
    app.revoke_through_generation(DEVICE,claim['generation'],now=NOW+1)
    with pytest.raises(PermissionError,match='generation revoked'):
        renew(rig,parent,claim,now=NOW+2,requested_at=NOW+2)


def test_new_independent_consent_after_epoch_gets_higher_generation(rig):
    app,human,_=rig
    _,first=approved_grant(rig)
    app.revoke_through_generation(DEVICE,15,now=NOW+1)
    packet=app.issue_approved_partial(consent_packet(human,decision_id='f'*64,
                                        decided_at=NOW+2,expires_at=NOW+122),
        expected_subject=SUBJECT,expected_device=DEVICE,now=NOW+2)
    assert json.loads(packet)['grant']['generation']==16


def test_clock_rollback_blocks_issuance_and_renewal(rig):
    app,human,device=rig
    parent,claim=approved_grant(rig)
    renew(rig,parent,claim,now=NOW+30,requested_at=NOW+30)
    with pytest.raises(PermissionError,match='rollback'):
        app.issue_approved_partial(consent_packet(human,decision_id='c'*64),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW+29)
    with pytest.raises(PermissionError,match='rollback'):
        app.renew_short_lease(parent,renewal_packet(device,claim,request_id='d'*64,
                                                    requested_at=NOW+29),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW+29)


def test_db_cannot_be_reset_by_reinitializing(rig):
    app,_,_=rig
    with pytest.raises(FileExistsError):
        app.initialize(NOW)


def test_db_symlink_or_world_writable_is_rejected(rig):
    app,_,_=rig
    db=app.db
    db.chmod(0o666)
    with pytest.raises(PermissionError):
        app.revoke_through_generation(DEVICE,1,now=NOW)
    db.chmod(0o600)
    db.rename(app.directory/'real')
    db.symlink_to(app.directory/'real')
    with pytest.raises(PermissionError):
        app.revoke_through_generation(DEVICE,1,now=NOW)


def test_root_only_and_locked_directory(rig,monkeypatch):
    app,_,_=rig
    monkeypatch.setattr(m.os,'geteuid',lambda:1000)
    with pytest.raises(PermissionError):
        app.revoke_through_generation(DEVICE,1,now=NOW)


def test_repeated_device_requests_under_parallel_workers_single_lease(rig):
    app,human,device=rig
    parent,claim=approved_grant(rig)
    packet=renewal_packet(device,claim)
    context=multiprocessing.get_context('fork')
    q=context.Queue()
    def worker():
        try:
            a=m.ProfileLeaseIssuerLab(app.directory,issuer_key=app.issuer_key,
                human_approval_key=public(human),device_keys={DEVICE:public(device)})
            result=a.renew_short_lease(parent,packet,expected_subject=SUBJECT,
                                        expected_device=DEVICE,now=NOW)
            q.put(('success',result))
        except Exception as exc:
            q.put((type(exc).__name__,str(exc)))
    processes=[context.Process(target=worker) for _ in range(8)]
    for process in processes: process.start()
    outcomes=[q.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode==0
    assert sum(outcome[0]=='success' for outcome in outcomes)==1
    assert sum(isinstance(outcome[1], str) and 'UNIQUE' in outcome[1]
               for outcome in outcomes)==7


def test_all_valid_partial_duration_values(rig):
    app,human,_=rig
    for index,seconds in enumerate(sorted(m.DURATIONS)):
        raw=app.issue_approved_partial(consent_packet(human,
            decision_id=f'{index+1:064x}',duration_seconds=seconds),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)
        assert json.loads(raw)['grant']['expires_at']==NOW+seconds


def test_expired_human_consent_denied_after_validity_window(rig):
    app,human,_=rig
    with pytest.raises(PermissionError):
        app.issue_approved_partial(consent_packet(human),
            expected_subject=SUBJECT,expected_device=DEVICE,now=NOW+120)


def test_claim_is_not_a_sudo_command_or_shell(rig):
    parent,claim=approved_grant(rig)
    assert claim['capabilities']==['root-identity-check']
    assert 'shell' not in parent.decode().lower()
    assert not hasattr(rig[0],'execute_root')



def test_target_rejects_issuer_lease_bound_to_different_signed_boot(rig):
    # Issuer cannot independently know a target's current boot. The pinned
    # device key authenticates its request; the LOCAL root verifier enforces
    # that its own kernel boot_id matches that signed request.
    app,_,device=rig
    parent,claim=approved_grant(rig)
    different_boot='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    issued=app.renew_short_lease(parent,
        renewal_packet(device,claim,boot_id=different_boot),
        expected_subject=SUBJECT,expected_device=DEVICE,now=NOW)
    grant=verify_signed_grant(parent,trusted_public_key=app.issuer_public,
        expected_device=DEVICE,expected_subject=SUBJECT,now=NOW)
    with pytest.raises(PermissionError,match='boot|bound'):
        verify_short_lease(issued,trusted_public_key=app.issuer_public,
                           grant=grant,expected_boot_id=BOOT,now=NOW)
