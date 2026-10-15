# SSH offer protocol design

A device that passed user confirmation receives public connection metadata over its authenticated polling channel. The server must verify the approved request and use only a protected, allowlisted provisioner. The metadata includes the management public key, gateway SSH host public key and assigned loopback port. No private key is transferred. Production changes are not enabled by this document.

## Checkpoint: 2026-10-15

A strict public offer validator and a once-only staging method were committed to the GitHub repository. The new test file has been updated to require the gateway host key from an independent trusted source. The developer's remote file writes were intermittently blocked, so the **new offer tests are not verified yet**. The preceding baseline of 35 tests remains separate from this increment.

Production registry, SSH credentials, port 10002 and the staged port 10003 were not changed. An offer still cannot activate a tunnel or grant privileges by itself. The next stage is to run the tests and implement an audited, narrow server-side provisioner rather than enabling arbitrary administrative commands.


## Implementation update: 2026-10-15 — Linux offer validation and HTTP tests

The previous note that the new tests were unverified is now historical.
GitHub Actions run https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38767537119
passed **48 isolated device-code tests**.

The Linux CLI now checks exact offer schema, request/device binding, fingerprints,
Restricted mode, persistence, fixed Gateway SSH host/user/port, loopback listener,
management public key, and a separately trusted local Gateway SSH host public
key pin. It rejects swapped keys, altered identities or ports, unexpected
fields, unapproved offers, missing pins, and status not bound to the request.
The real loopback HTTP polling test delivers a staged, approved public offer
into the Linux validator without installing anything. The HTTP pairing client
also rejects all redirects; regression tests verify that secrets are not
forwarded to a redirected endpoint.

Commits: b9ff708, 0b6c503, 2383429, 5f9fc02, 3baaa97.
The CLI supports --trusted-gateway-host-key PATH, a non-symlink local file
owned by the user or root and not writable by group/others. This trust pin
must be distributed via an independently verified release or operator path:
it must not be learned from the very offer it is validating. The existing
bootstrap installer remains pinned to its older release. Do NOT update its
hash or version until a full candidate release is reviewed.

**No Oracle production deployment, SSH credential change, or cutover occurred.**
The existing v1/v2 services remain intact. The new device-code public API
and MCP confirmation path are not live. There is still no installed narrow
root-owned SSH provisioner, no active candidate tunnel on 10003, and no
fully automatic device enrollment.

**Next agreed step:** implement and test the narrow, audited server-side
candidate provisioner and corresponding Linux-local configuration in an
isolated laboratory, before any root deployment. Define and test controlled
inputs, per-device identities, port allowlists, host-key pinning, negative
cases, rollback and independent approval. Preserve the WSL legacy tunnel
10002 and do not introduce generic sudo or revoke existing credentials.


## Checkpoint: 2026-10-15 — isolated candidate provisioning (no production changes)

GitHub Actions run https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38772295681
passed **56 device-code tests, no failures**. This supersedes the prior
48-test checkpoint.

### New laboratory implementation

- The internal DeviceCodeStore.approved_candidate_snapshot() returns a
  narrow *public-key-only* record only after proof of possession, verified
  operator code confirmation and still-valid approval. It normalizes the
  SQLite integer connection preference to a real bool. This method is NOT
  an HTTP or MCP endpoint and is NOT an authorization to run privileged code.
- src/ai_lab_gateway/device_code_candidate.py implements the WSL PILOT
  candidate preparation only: device windows-wsl, Restricted, on-demand,
  loopback port 10003 (legacy 10002 stays untouched). It generates a distinct
  management Ed25519 private key within a nonroot, isolated owner-only sandbox
  and prepares the tunnel's permitlisten-only authorized_keys append fragment,
  the Gateway's known_hosts fragment, a management-key append fragment for
  the target, and an immutable public offer.
- Stage operations create only a separate private laboratory directory.
  Failure of DB offer staging removes the new directory, not existing data.
  No real authorized_keys, known_hosts, sshd, systemd, sudoers, Gateway device
  registry, target account, or current key is modified.
- scripts/device_code_pair_linux.py additionally validates the SSH offer
  against an independently obtained Gateway SSH host key pin and creates
  *inert local fragments* in its owner-only state directory on first
  acceptance. It does not install/configure SSH or start a tunnel.
- Added tests/test_device_code_candidate.py, plus Linux-local staging
  regression tests covering approval, short TTL, identity separation,
  port restrictions, no priv escalation, 0600 key files, wrong pins,
  symlinks, duplicate candidates and staging rollback.

### Critical distinctions and known blockers

1. This is NOT a running root-owned SSH provisioner. The lab intentionally
   forbids execution as root; its direct internal store call and
   provisioner_verified=True staging flag are NOT acceptable production
   authorization boundaries. Production requires a separate root-owned,
   strict UID/policy-checked IPC adapter and its own rollback, port locking,
   SSH restrictions, audit and recovery tests.
2. The current code targets the already registered WSL pilot first. It is
   not yet generic new-Linux enrollment. Do not prematurely open arbitrary
   reverse ports or create root privileges.
3. A freshly generated device host identity is not necessarily the SSH host
   key served by its sshd. For the existing WSL pilot use its independently
   verified actual sshd host public key (or explicitly install/verify the
   new one) before counting any SSH acceptance.
4. The independently trusted Gateway SSH host public-key pin is NOT yet
   distributed by the pinned Linux bootstrap; do not trust a key solely
   because it appears in a server offer.
5. Public device-code HTTPS endpoints and real Auth0 MCP confirmation
   remain UNDEPLOYED. The independent consent boundary is not replaced
   by a model-generated call; browser approval fallback stays intact.
6. Source code and tests on GitHub do not prove successful tunnel setup,
   verified management login, reconnect, atomic registry cutover or root
   administrative rollback. No existing v1 credentials may be revoked yet.

### Next planned implementation (same scope)

Implement the controlled server-side root provisioner adapter using root-
owned configuration and a protected peer-authenticated handoff; verify
approved-state binding again before modifying any system-owned SSH file.
Add candidate-only atomic append, strict permission checks, immutable key
fingerprints, SSH negative tests and real rollback coverage in a sandbox.
Then implement local narrow administration and full WSL acceptance while
keeping the 10002 management channel intact. Only after this should the
operator consider an approved Oracle rollout. No multi-platform or
multi-user expansion is part of the immediate plan.


## Checkpoint — 2026-10-15: protected staging RPC and SSH file rehearsal

**Verified:** GitHub Actions https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38773951543
passed **72 isolated device-code tests** on the commit ff7e558d27de.
Earlier failed runs were investigated and repaired before this successful run.
These tests remain laboratory evidence, not production acceptance.

New candidate-provisioning work:
- src/ai_lab_gateway/device_code_provision_rpc.py introduces a NONROOT
  Unix-domain laboratory RPC boundary with kernel SO_PEERCRED UID checks,
  owner-only 0700 socket directory, 0600 socket, hard payload limits,
  and exactly one action (stage_wsl_candidate). The caller submits only
  request_id; device ID, keys, port, paths, sudo flags, access mode and
  commands are not accepted. Unapproved/expired/replayed requests fail closed
  without exposing credentials or database internals.
- tests/test_device_code_provision_rpc.py exercises real Unix sockets and
  UID rejection, forbidden parameters, one-time staging, rejection of
  unapproved/expired sessions, private files and rollback on DB staging error.
- DeviceCodeStore.staged_candidate_snapshot() rechecks approval state,
  expiry and immutable offer presence before sandbox installation rehearsal;
  it is internal only, not an MCP or HTTP tool.
- src/ai_lab_gateway/device_code_candidate_files.py rehearses fixed-port
  WSL candidate authorized_keys and known_hosts appends against two fixed
  mock files inside sandbox_root/mock-gateway. It verifies the immutable
  DB-backed offer, trusted independent Gateway SSH host-key pin, exact
  tunnel/host/management public keys, candidate fragments, file ownership,
  modes and no-symlink invariants. It uses a local advisory file lock,
  fsync + os.replace and restores the original first file on a simulated
  second-stage error. The unit tests also cover tampering, wrong pins,
  replay, expired authorization, unsafe modes/symlinks and path traversal.
- tests/test_device_code_candidate_files.py verifies that existing
  mock credentials remain intact across denied operations and rollback.
  No live sshd, keys or registry were touched.

**Critical distinction:** Nothing here is a privileged production
provisioner. This laboratory deliberately refuses root execution and cannot
modify any system-owned SSH file. Passing the current suite does NOT prove
durable crash-safe cross-file transactions, correct ownership under real
root, port reservation, exact runtime policy, independently authorized
root-owned IPC, or full SSH acceptance. The Boolean
provisioner_verified=True in the isolated store is not authorization from a
human and MUST NOT become a callable parameter of any production interface.

Before activation, implement a standalone root-owned service with strict
peer-UID checks, allowlisted root-owned source paths and policy, atomic
candidate-only installation with journaled crash recovery, root-controlled
key/port reservation, audited operator approval, and negative SSH tests.
Use the actual sshd host key of the target (or deliberately provision one)
and verify it before connection is considered trusted. Keep both WSL port
10002 and Raspberry port 10001 working. After independent device-side
installation, test candidate 10003 and perform controlled cutover only after
rollback/reconnect/negative tests. The new device-code public API and MCP
consent/confirmation remain not deployed.


## Checkpoint — 2026-10-15: crash journal, read-only approval handoff and root preflight

Verified in GitHub Actions:
https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38795669180
**88 isolated device-code tests passed, zero failures**, including six
new crash-journal tests, five approval-handoff tests and five root-policy
preflight tests. Prior 72-test result remains historical.

New modules and work:
- src/ai_lab_gateway/device_code_candidate_journal.py: nonroot-only,
  crash-recoverable two-file mock SSH transaction. A private durable JSON
  journal is fsync'ed before either replace; recovery uses an exclusive
  flock and checks exact original or planned-new content digests, refusing
  unexpected external changes. A pending journal blocks new installation.
  Tests simulate abrupt death after the first or second file replacement,
  explicit recovery, corruption, concurrent modification and replay.
  The older mock rehearsal now uses this journaled transaction.
- src/ai_lab_gateway/device_code_approval_handoff.py: separate,
  read-only Unix approval-handoff prototype with SO_PEERCRED, exact
  request-only schema and strict UID gate. It returns ONLY the approved
  candidate's public identities and immutable offer. It exposes no approve,
  root, provision, activate or SSH mutation actions. Tests exercise a real
  Unix socket, wrong UID, expiry, nonexistent approval, forbidden inputs,
  private socket permissions and sensitive-field exclusion.
- src/ai_lab_gateway/device_code_root_preflight.py: pure/read-only WSL
  candidate policy gate. It compares the handoff with independently
  established Gateway SSH host key, actual sshd target host key, generated
  management public key, exact Restricted/on-demand mode and protected
  registry (existing WSL port 10002, candidate unassigned 10003). Tests
  cover identity replacement, privilege escalation, duplicate registry
  devices, occupied assigned ports, malformed entries and pin mismatch.

Implementation is in the existing plan: restricted-first Linux v2 pairing
starting with the already registered WSL, not OpenWrt, native Windows or
multiuser.

**Not deployed, not production-root-capable.** The journal only modifies
two 0600 mock files in a nonroot sandbox. Crash testing uses injected
process-death exceptions, not physical VM failure. The approval handoff
is a nonroot laboratory socket; production must allow ONLY the actual
root-owned installer UID and keep the pairing store privately owned by
its independent service. Root-preflight inputs must originate from
root-owned trusted sources; the pure validator does not authenticate those
sources itself and does not reserve a listening port.

**Production blocker remains:** build/review/authorize a true independent
root-owned service with peer UID confinement, controlled secure source paths,
port reservation, independently verified human approval, real Linux file
ownership, crash-safe rollback and audit. Verify target sshd's real host
identity, install only the WSL 10003 candidate, run positive and negative
SSH tests and reconnect/rollback before registry switch. Do not turn
the lab store's provisioner_verified Boolean into a trusted root permission.
Do not grant sudo on pairing or revoke WSL 10002. Public device-code API and
MCP confirmation are still not live.


## Checkpoint — 2026-10-15: fixed root-owned read-only preflight service code

**GitHub Actions verified:** https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38817253195
**110 isolated device-code tests passed; no failures.** The preceding
88-test checkpoint is preserved for chronology.

New code and tests:
- src/ai_lab_gateway/device_code_root_environment.py verifies fixed SSH
  file identities and permissions, parent directories, no symlinks or
  multiple hard links, protected registry, the effective sshd -T tunnel
  account restrictions, and the vacant loopback candidate port 10003.
  Secure file reads use O_NOFOLLOW and fstat of the opened descriptor.
  It checks the candidate's gateway/target SSH host keys against
  separately trusted local sources and proves the management public key
  matches a locally held management private key using ssh-keygen -y.
  The actual production entrypoint has hard-coded paths and requires UID 0.
- src/ai_lab_gateway/device_code_root_preflight_rpc.py defines a root-owned,
  STRICTLY READ-ONLY Unix preflight socket. The kernel SO_PEERCRED must
  identify the ai-lab-gateway UID; its request accepts only an existing
  request_id, no device, port, path, key, permission, sudo, shell, approve,
  install or activate actions. The socket must be created by root with
  owner=root, group=ai-lab-gateway, mode=0660 and inside a root-owned,
  group=ai-lab-gateway 0750 directory. Its root constructor obtains the
  already-approved candidate through the protected approval handoff and
  checks root-owned local sources, not caller-supplied metadata.
- scripts/run_device_code_root_preflight.py is an optional, standalone
  read-only entrypoint: it refuses nonroot invocation, requires an exact
  root-owned 0400 out-of-band enable marker at
  /etc/ai-lab-gateway/device-code-root-preflight-enabled and recognizes
  only --serve-read-only. This marker has NOT been created; the script
  has NOT been installed, started or exposed.
- tests/test_device_code_root_environment.py, root_preflight_rpc.py and
  root_startup.py cover SSH file/link/mode/owner checks, independent
  fingerprints, possession of management private key, effective sshd
  restrictions, registry/port mismatches, kernel UID access, rejection
  of forbidden RPC actions, socket ownership and disabled-by-default
  startup. The GitHub Actions workflow now also watches the root runner.

**Production limitations:** This is code for a potential restricted root
*preflight service*, NOT the privileged file-mutating installer. It has
no production unit, no root installation, no active pairing-code endpoint,
no root-owned candidate key provisioned by this flow, no active WSL 10003
tunnel and no registry switch. Real root-side source-file ownership and
effective sshd checks have not been run in production.

A particularly important acceptance constraint is that the Linux
client's default, separately generated host-ed25519 identity is NOT
automatically the key served by the device's sshd. For the current WSL
pilot, pair with the independently verified actual sshd host public
key (via the client's supported --host-key option) or explicitly
install/verify a dedicated host key before enabling 10003. Never silently
trust a new host key learned from the offer.

**Next agreed step:** implement and review a separate narrow root-owned
*apply* operation with verified approval at commit time, root-generated
management credentials, protected SSH paths, fixed port allowlists,
port reservation, durable root-owned transaction and crash recovery,
audit and negative SSH acceptance. Prepare a trusted device-local
installer that can finish host key/user/service setup while preserving
10002. This is not a change of scope: WSL first, restricted-first,
on-demand persistence, no new features or platform expansion.
