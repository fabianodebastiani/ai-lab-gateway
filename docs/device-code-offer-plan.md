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


## Checkpoint — 2026-10-15: root-owned candidate SSH transaction and disabled apply service

**Verified Actions run:**
https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38821352926

- **General job:** 137 test cases discovered; 124 executed successfully,
  13 actual-root cases intentionally skipped in the unprivileged job.
- **Isolated root job:** those **13 tests ran as real UID 0 on an
  ephemeral GitHub Actions machine and all passed**. Together the jobs
  cover **137 distinct passing test cases**.
- A prior CI attempt had an intermittent BrokenPipeError in the
  wrong-UID rejection test because the kernel closed the unauthorized
  socket before the client finished writing. The regression test now
  recognizes a connection reset as a valid fail-closed denial. Both
  jobs passed after the correction.

### Implemented in source (NOT installed on Oracle)

1. `src/ai_lab_gateway/device_code_root_transaction.py` — a root-only,
   two-file SSH staging transaction core. It preserves distinct owner
   UIDs/GIDs and 0600 permissions for tunnel authorized_keys and
   Gateway known_hosts, writes root-owned fsync'ed undo journal and audit,
   checks file ownership, types, links, modes and content under an
   exclusive lock, and refuses duplicate candidate port 10003.
   Explicit recovery restores the old bytes only if current files match
   original/planned hashes. All old 10002 credentials remain present.
2. Root CI uses real `os.fchown`, `fsync`, `os.replace`, and a
   separate actual root worker process terminated abruptly via
   `os._exit(137)`. The next root process recovered the pending journal.
   This tests process-exit recovery, NOT VM power failure or disk corruption.
3. `src/ai_lab_gateway/device_code_root_environment.py` supports
   revalidating trusted fixed paths while a live socket reserves
   `127.0.0.1:10003` (not a public listener). The production adapter
   must keep that reservation from before the first validation until
   after the two-file transaction.
4. `src/ai_lab_gateway/device_code_root_apply.py` — a dedicated
   root-only, exact-action candidate SSH staging RPC. The kernel
   `SO_PEERCRED` restricts callers to the `ai-lab-gateway` UID. The
   only accepted action is `apply_wsl_candidate(request_id)`.
   Device, port, SSH keys, path, command, sudo, bypass flags,
   registry and activation requests in the caller payload are refused.
   The independent approval handoff and root-owned SSH environment are
   rechecked immediately inside the journal lock before any changes.
   Successful staging does NOT change the registry or activate the WSL.
5. `scripts/run_device_code_root_apply.py` is a separate,
   **disabled-by-default** root-only entrypoint, gated by an exact
   root-owned 0400 administrative marker
   `/etc/ai-lab-gateway/device-code-root-apply-enabled`.
   This marker has NOT been created. The service has NOT been installed.
6. `scripts/recover_device_code_root_candidate.py` is a separate
   manual root-console-only recovery entrypoint, with fixed destinations
   and no arbitrary command, user, file path or port selection; the
   apply socket explicitly rejects recovery requests. NOT installed.
7. New tests cover real root file ownership, wrong permissions, symlink
   rejection, port conflicts, approval revoked between checks,
   independent approval checks at commit, abrupt root process exit,
   missing/corrupted journal, unrecognized actions, exact UID
   verification, off-by-default marker, and preservation of the old
   registry and credentials.

### Deployment blockers — do not mistake successful source tests for cutover

- No production root apply service/socket/unit, enable marker, fixed
  journal directory or candidate management identity has been installed
  through this flow. The fixed root preflight currently requires a
  separately verified management private/public keypair that the
  new device-code candidate must obtain from a trusted root-controlled
  provisioning step before staging can succeed.
- The production approval handoff and new device-code HTTPS/MCP endpoints
  remain off. Root code refuses staging in their absence.
- Existing WSL sshd actual host identity must be verified and match
  the approved offer; the client's own generated host key does NOT
  automatically become the sshd host key.
- Real Oracle-owned directory layout, exact service UIDs and sshd -T
  restrictions still require a supervised dry run. The root file-writing
  core has been exercised only on disposable GitHub Actions paths.
- The root transaction changes ONLY two SSH candidate files. It never
  edits the device registry, changes the WSL target SSH account,
  launches the 10003 tunnel, proves real management login, or revokes
  the old port 10002 identity. A separate device-side installer,
  end-to-end negative tests, atomic registry cutover and rollback
  remain mandatory.
- Approval marker creation, privileged root installation and cutover
  are reserved for human-supervised administrative deployment. No
  general passwordless sudo is introduced through MCP.

**Last read-only production check (15 Oct):** Oracle MCP and Raspberry
online, five Oracle services active, 10001 loopback listener present.
WSL 10002 was offline (the known on-demand mode); candidate 10003
remains not listening. The new `/pairing/device/health` still returns
HTTP 404. No production services, credentials or policy were altered
during this development step.

**Next task:** implement a root-controlled candidate management identity
creation/verification transaction, complete the separate target-side
nonroot installer, and perform a supervised Oracle preflight review.
Do not install/enable root apply until those prerequisites and the
independent human approval mechanism are verifiably wired.


## Checkpoint — 2026-10-15: supervised root SSH management identity

**GitHub Actions verified:**
https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38824505117

**143 distinct passing tests, no failures:** the unprivileged job
discovered 143 cases, passed 125 and correctly skipped the 18 tests
requiring actual UID 0; the separate root job ran all 18 root cases
successfully (13 SSH transaction, 5 new independent identity tests).

### Implemented but not deployed

- `src/ai_lab_gateway/device_code_root_identity.py`: one-time WSL
  candidate management Ed25519 identity creation at an *exclusive root
  controlled* key directory. Private and public files are owned
  `root:ai-lab-gateway` with 0640; the dedicated candidate directory
  and its parent are `root:ai-lab-gateway` 0750. Only root can publish
  or replace files; the Gateway group can read the private key without
  owning/writing it. A root-only lock, temporary directory, fsync and
  atomic rename prevent publishing half-generated key pairs.
  Repeated generation is refused. This key is unrelated to the current
  WSL v1 (10002) identity; no live SSH credential is installed.
- Key derivation is tested from the perspective of the **actual
  unprivileged service UID** by `/usr/bin/setpriv` then
  `/usr/bin/ssh-keygen -y`. This is necessary: OpenSSH rejects a
  root-owned private file with group-readable 0640 when ssh-keygen
  runs as root itself. Tests use the genuine CI `nobody` passwd
  account as the unprivileged stand-in. There is no private key
  disclosure to an RPC/ChatGPT client.
- `src/ai_lab_gateway/device_code_root_environment.py`: fixed-path
  production preflight now reads the independent candidate public key
  ONLY after `verify_wsl_management_identity` has checked its
  root-owned files and derived the matching public identity as the
  Gateway UID. The laboratory unit-test file injection remains
  separate; passing a model-provided key to the production wrapper
  is not possible.
- `scripts/prepare_device_code_root_identity.py`: manual,
  root-only, fixed WSL-10003 preparation and verification CLI with no
  path, uid, port, command, sudo or key material arguments. The
  parent directory is intentionally NOT created automatically. The
  command is NOT installed on the Oracle and cannot be invoked
  through the MCP interface.
- Tests added: `tests/test_device_code_root_identity.py` (five
  real-root tests: one-time generation, exact owner/group/modes,
  wrong owner/mode denial, nonroot denial, tampering and symlink
  refusal), plus a production-style pinned-management-key test in
  `test_device_code_root_environment.py`.
- A first CI implementation failed because the OpenSSH root owner
  rejected group-readable permissions. A second attempt failed
  because synthetic UIDs lacked passwd entries. Both were corrected,
  and the final entire workflow succeeded, including actual
  root/nonroot key read permissions.

### Production read-only inspection

The Oracle continues to have `ai-lab-gateway` and `tunnel`
separate Unix accounts. `/etc/ai-lab-gateway` exists as
root:ai-lab-gateway mode 0750; the candidate
`/etc/ai-lab-gateway/device-code-keys` directory and candidate
apply socket do NOT exist. `setpriv` and `ssh-keygen` exist.
Existing source-code assumptions about real `authorized_keys`
and `known_hosts` locations have not yet been reconciled with
their actual root-owned production paths, so even a correct key
alone does NOT make root apply deployable.

### Open prerequisites and next task

1. Inspect and reconcile **actual** Oracle SSH/authorized_keys/
   known_hosts/registry paths, service users, effective sshd policy
   and the WSL target's real sshd host public key. Prior preflight
   constants may not match the current Oracle filesystem. Fail
   closed until root independently verifies the specific files.
2. Build a supervised *root-only* installation package/checklist,
   with verified release hash, immutable inputs, journal root directory
   and ready-to-test dry-run. No remote privileged operation without
   explicit human/admin action.
3. Integrate candidate offer staging with this root-owned
   management public key. The older nonroot laboratory candidate
   generator still produces its own separate key; it is NOT
   automatically connected to the root identity.
4. Enable public HTTPS device-code endpoints and Auth0-confirmed MCP
   only after the independent consent boundary and broker have been
   deployed and verified.
5. Configure the target WSL, validate 10003 positive/negative SSH
   tests, on-demand reconnect and rollback while preserving old
   10002, then perform separately authorized registry cutover.

The new code has NOT created keys on the real Oracle, changed
production SSH files, started 10003, granted sudo, or revoked
the existing WSL v1 account or tunnel.


## Checkpoint — 2026-10-15: investigate Oracle protected paths (no privilege escalation)

**Test evidence:**
https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38827356501
passed **151 distinct cases** (133 standard successes and 18 root
cases skipped in the standard job; all 18 root cases ran/passed in
the isolated GitHub root job).

**Verified actual MCP identity:** `exec(oracle-gateway)` runs as
`ai-maintenance`, UID/GID 1003 — NOT as root or `ai-lab-gateway`.
`/etc/ai-lab-gateway` is inaccessible to this identity, so
`test -e` saying false is NOT proof that a protected file is absent.
Similarly `sshd -T` fails without root-readable host keys and
does NOT establish effective sshd policy. Do not make security claims
from these inaccessible paths.

Unprivileged read-only observations: `ai-lab-gateway.service` uses
the `ai-lab-gateway` account and
`/opt/ai-lab-gateway/.venv/bin/ai-lab-gateway`; the tunnel account's
home is `/var/lib/ai-lab-tunnel`. Oracle and Raspberry MCP are online,
five Oracle services active; loopback 10001 is listening, WSL
on-demand 10002 offline, candidate 10003 absent. Pairing v1/v2
health still works and new code-pairing health remains HTTP404.

**New safe root-only audit (source created, NOT run in Oracle root):**
- `src/ai_lab_gateway/device_code_root_inventory.py` resolves the
  actual device registry from the live service PID's allowlisted
  environment value, or default when truly absent; resolves effective
  tunnel `authorizedkeysfile` using root `sshd -T`; reports only
  lstat metadata and registry device IDs, ports and SSH path names.
  Never prints secrets, private key bytes, passwords or arbitrary
  environment values. An expected `known_hosts` location is only an
  inference until effective SSH-client configuration is verified.
- `scripts/audit_device_code_production.py` accepts exclusively
  `--audit-paths-only` and requires actual root in a separately
  human-authorized console. Not installed or exposed over MCP.
- `tests/test_device_code_root_inventory.py` has eight tests for
  environment allowlisting, path traversal, sshd relative paths,
  symbolic links, access failures, root-only enforcement and no
  secret leakage.
- New explanatory document:
  `docs/device-code-production-inventory.md`.

**Production blocker unchanged:** hardcoded root transaction paths
are still hypotheses until the independent root audit resolves the
true registry, tunnel authorized_keys, Gateway known_hosts and
effective SSH service policy. No root apply installation/candidate
SSH edits/registry switch should occur based on uncertain paths.

**Next:** perform the reviewed read-only root-console audit through
separate explicit administrator action, compare it with the current
code, then adjust and retest root-owned path/ownership constraints.
No attempts to bypass sudo, and no new service/port activation.
