# One-code enrollment: last-mile SSH activation — checkpoint

**Status:** implementation candidate, **not a completed end-to-end connection**.

## Verified facts

- User submitted a single code in authenticated ChatGPT. The Gateway's
  `pairing_lookup_code` identified `LAPTOP-5RJJ0KBM`, requested device
  `laptop-5rjj0kbm-8210ee98`; the user explicitly approved it and
  `pairing_confirm_single_code` returned `status=approved`,
  `access_mode=restricted`. This approves the *pending identity* only.
- That particular installer was run with **`--no-wait`**. It discarded
  the in-memory polling secret upon exit, so there is no running process
  to receive an SSH offer. The 10-minute enrollment approval deadline is
  not extended by ChatGPT text. A subsequent complete test must initiate
  a **new** session only after the server-side provisioner is operational.
- The old WSL `10002` and Raspberry `10001` listeners remain active;
  `10003` has not been enabled. The independent, time-limited Oracle
  maintenance sudo expired at 2026-10-16 01:40:36 UTC. Its successful
  revocation was observed; the MCP currently has **no sudo**.
- On the real WSL, `/etc/ssh/ssh_host_ed25519_key.pub` is available;
  its fingerprint is
  `SHA256:hh1guyo4yOa81Qj0zrf+XZlNpwaMlH0BfDAdo0SGwCw`.
  The old Oracle host pin for WSL port `10002` matches it; an entry
  for candidate port `10003` already has the same ED25519 host identity.
  Old preflight code incorrectly treats this benign preexisting pin
  as a hard conflict. Do not overwrite or duplicate it.
- Existing WSL `ssh.service` and `systemd --user` are available.
  A rootless transient user service was smoke-tested with
  `systemd-run --user --collect --wait /usr/bin/true`; the original
  WSL SSH tunnel remained active.

## Candidate Linux client improvement

`scripts/device_code_pair_linux.py` now:
1. Uses the **real local OpenSSH server's** ED25519 public host key on
   HTTPS enrollment when already installed (local HTTP tests retain
   synthetic staging keys).
2. Waits for the authenticated, approved, trusted public connection offer;
   verifies the independently pinned Gateway SSH host key and the
   local `ssh-keyscan` identity before beginning activation.
3. For an **existing nonroot management user with sshd already running
   and on-demand connectivity only**, manages the authorized_keys public
   entry and initiates a loopback-only `ssh -R` using user systemd.
   It refuses root, elevated access modes, untrusted keys, symlinked
   authorized_keys, wrong management user or unmatched local sshd.
4. Does NOT grant sudo, install an sshd, enable perpetual startup,
   reassign registry entries, authorize itself, or bypass host-key checks.

The bootstrap now pins the matching source commit/SHA256 plus the
independently verified public Oracle SSH host identity in its
versioned HTTPS-distributed script. This is **not** a complete release
signature or proof of host-native consent.

## Still required before a live activation

- Narrow, independently authorized **Oracle root-side SSH provisioning**
  that reads the exact approved identity; checks short TTL/replay,
  generates a separate Gateway management identity, provisions per-device
  tunnel key and verified loopback host pin, and delivers a signed/bound
  public offer back to the existing device-code service.
- The existing root preflight/transaction suite is hardcoded to
  `windows-wsl` and port `10003`. The user's new device ID is different,
  and the 10003 host pin is pre-existing. Adapt safely without bypassing
  identity checks or replacing the old WSL connection.
- Independent SSH success and negative permission checks, then atomic
  registry and Auth0-subject authorization-policy addition. Until that
  completes, `list_devices` must **not** claim the new identity exists.
- Manage local rollback if a launched tunnel never becomes active
  before approval expiry. Implement persistent=true separately; this
  WSL pilot only tests persistent=false.
- Fresh Linux without an OpenSSH server will require a local
  OS installation/administrative step within the installer. A temporary
  nonroot-generated host key is **not** proof of a running sshd.
- Explicit operator consent in the current ChatGPT conversation exists,
  but native host-attested authorization is not independently established.
  Preserve the existing independent consent fallback until validated.

No broad sudo was re-granted, no Oracle SSH authorized_keys, known_hosts,
policy, registry or root service was altered in this implementation turn.
**Do not merge/deploy this SSH autoactivation candidate as a completed
product until the next root-side proof and end-to-end tests pass.**
