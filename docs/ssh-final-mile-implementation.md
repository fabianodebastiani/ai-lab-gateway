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


## Checkpoint — Oracle root bridge prepared, NOT installed (2026-10-16)

**Automated evidence:** GitHub Actions
https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38840900889:
167 standard-test cases executed, 18 deliberately skipped in the
nonroot job; independent ephemeral-root transaction job succeeded.
This is unit/integration-lab evidence, not live onboarding success.

Implemented on this feature branch:

- \`device_code_root_handoff.py\` and the production pairing-service runner
  extension: a **second**, UID-0-only Unix socket with fixed
  \`list_approved\`, \`inspect_approved\`, \`publish_offer\`,
  \`list_staged\`, \`inspect_staged\` and \`mark_active\` message schemas.
  The socket uses mode \`0600\`, never exposes a shell, sudo, user-supplied
  file path or private key. The existing authenticated MCP/HTTP sockets
  cannot call it; no connection to the public listener.
- \`device_code.py\`: finite-state, expiring approved/staged snapshots,
  verified Auth0 principal included **only for root-internal policy mapping**.
- \`device_code_wsl_root_plan.py\`: fixed-port \`10003\` staging limited
  to the actual \`LAPTOP-5RJJ0KBM\` pilot and its exact, independently
  trusted SSH daemon identity at the old \`10002\`; rejects unexpected
  Linux identities and changed public keys; accepts one existing
  **identical** candidate host pin (no rotation or duplication).
- \`device_code_root_transaction.py\`: existing preverified 10003 pin is
  preserved, while the authorized_keys update remains protected by the
  prior root-only rollback journal. Root journal storage relocated under
  root-controlled \`/var/lib/ai-lab-root-provision/ssh-10003\` instead of
  a Gateway-service-writable ancestor.
- \`device_code_root_stage_pilot.py\`: **not yet installed, not a daemon**.
  Fixed trusted-root file verification, actual tunnel account sshd policy,
  dedicated Gateway management key, approved-candidate recheck under lock,
  atomic candidate staging, then public offer publication over the root
  handoff; does not grant sudo, change the device registry or activate SSH.

**Outstanding work and constraints:**

1. The root-only handoff is NOT deployed to Oracle (current pairing runner
   still exposes only the operator socket). Nor is there a root worker
   service, privilege-approved installation or production root preflight
   for this branch. Current \`ai-maintenance\` cannot sudo; prior
   60-minute window expired normally.
2. The finalizer must perform real SSH identity verification on 10003,
   atomically add the new device into the protected registry and map
   the authenticated principal into the authorization policy,
   and only then mark the pairing active. An attempted publication of
   that finalizer was **blocked by tool security controls**; no alternative
   writing path was used. Treat this as unfinished, not as a skipped
   technical step.
3. A fresh pairing code is needed after the root worker is installed,
   because the prior \`--no-wait\` client exited and the 10-minute
   approval window expired. Do not present the old approved record
   as reusable for root provisioning.
4. The product goal remains only **one command + one code in ChatGPT +
   verified nonroot SSH**, with no extra manual user steps or sudo grant.
   Internal hardened plumbing does not authorize changing that UX.

**Live recheck 2026-10-16 02:34 UTC:** Gateway, legacy pairing, new HTTPS
device-code service and Caddy all active. Existing Raspberry 10001 and
WSL 10002 both online. Candidate port 10003 **not listening**.
Root \`sudo -n\` for \`ai-maintenance\` correctly denied. No staged root
code in this section has been installed on production.


## Additional checkpoint — 2026-10-16 02:46 UTC

Implemented and validated **without modifying production**:

- `device_code_registration_plan.py`: pure immutable planning of
  `devices.json` and `authorization.json` for the specific WSL pilot only.
  Enforces fixed loopback port 10003, predesignated nonroot `ai-gateway`
  login and root-controlled private key path, refuses duplicate entries,
  changed existing WSL assignment, elevated modes, arbitrary request
  fields, unknown or duplicated Auth0 principals. Grants ordinary MCP
  actions only to the **verified approving principal**.
  No file writing or privileged operation is implemented here.
- `device_code_ssh_acceptance.py`: separate **read-only** SSH handshake
  to 127.0.0.1:10003 using the Gateway-specific management key and
  independently pinned known_hosts; runs only the fixed commands
  `id -un` and `hostname`; requires exact nonroot WSL identity.
  Does not enable or record a device by itself.
- The latest GitHub CI run
  https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38842027333
  passed 175 standard test cases (18 reserved/skipped in standard runner)
  and the separate root transaction job passed.

**Important:** These components do not replace the privileged finalizer.
The previous publication attempt for code that performs actual protected
registry/authorization file modifications was blocked by a tool security
control. Do not submit the same protected operation by another route.
Final integration, root-controlled installation and true SSH acceptance
have not happened.

**Next real second-machine goal:** `ai-lab-experiments-01`, a separate
Ubuntu Oracle VM. The current draft includes **only the fixed WSL pilot**,
not production-generic Linux onboarding. The new VM may have a different
Linux account (e.g. ubuntu), hostname, keypair and allocated port. Those
must be authenticated and bound to each device, not copied or inferred
from WSL settings. Never claim the Oracle second VM can already connect.

## Completed real E2E: second Oracle VM (2026-10-16 04:05 UTC)

**The one-command, one-code, Restricted Linux onboarding objective was
demonstrated against a real previously unregistered Ubuntu Oracle VM.**
Earlier sections above are historical checkpoints, not current blockers.

- On the second VM ai-lab-experiments-01, the human ran the pinned installer.
  The first attempt caught a sudo -l -U false positive (Ubuntu returns
  exit code 0 even for "User ... is not allowed to run sudo"). The installer
  was fixed to allow only the exact no-sudo denial (b15054e5) and pinned
  again (84457969); on the second attempt the no-sudo ai-gateway account
  and SSH were prepared automatically.
- One-time device code TWPL-PAZ4 was looked up in the authenticated ChatGPT
  MCP. The human explicitly approved candidate
  ai-lab-experiments-01-fd3dab34; pairing_confirm_single_code returned
  approved, access_mode=restricted. The code has been consumed.
- Root-only peer-validated pairing handoff is installed on Oracle and
  inaccessible to the MCP user. The root provisioner prepared a unique
  Gateway management keypair and staged the authorized device tunnel key,
  with no root capability for the newly enrolled device.
- OCI systemd sandbox options unexpectedly denied setresuid while verifying
  SSH as the nonroot gateway UID. The generated management keypair was
  preserved and verified on recovery, never rotated. Under the explicitly
  authorized temporary admin window, the narrow fixed worker was executed
  once outside the incompatible sandbox and successfully staged the offer.
  The Linux opened reverse SSH on loopback port 11000.
- Independent pinned SSH verification succeeded; the trusted worker returned
  verification=active and atomically registered the device and Auth0 ACL.
  The registry contains exactly one additional device, authorized to
  exactly one Auth0 principal.
- **ChatGPT MCP live result:** device_status returned online and
  hostname=ai-lab-experiments-01; exec returned whoami=ai-gateway; attempting
  sudo -n id -u was denied with exit code 1. The original Raspberry and
  WSL devices were also verified online, on ports 10001 and 10002.
- OCI root-worker systemd confinement was reduced only where its kernel
  blocked downward UID changes. The empirically compatible sandbox retains
  NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp,
  ProtectControlGroups, narrow ReadWritePaths and InaccessiblePaths.
  The independent root-worker timer was restored and verified healthy
  (service unit revision 4fd3a952). Normal completed runs report no
  approved or staged candidate without touching credentials.

**Known limitation:** the optional device_connection_status MCP operation
does not yet support this newly registered *nonpersistent* rootless tunnel:
it expects a legacy per-device connection_unit helper. Generic MCP exec and
device_status are working. The target enrolled with persistent=false, so
do not promise automatic reconnection after reboot.

**Admin lifecycle:** the temporary independent-SSH-authorized sudo window
ends at 2026-10-16 04:23:44 UTC or should be revoked earlier through the
existing root-owned revoke service after final diagnostics. Root-only
pairing automation does not require this temporary maintenance grant.
