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
