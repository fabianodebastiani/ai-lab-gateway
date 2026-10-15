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
