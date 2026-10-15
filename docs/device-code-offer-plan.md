# SSH offer protocol design

A device that passed user confirmation receives public connection metadata over its authenticated polling channel. The server must verify the approved request and use only a protected, allowlisted provisioner. The metadata includes the management public key, gateway SSH host public key and assigned loopback port. No private key is transferred. Production changes are not enabled by this document.

## Checkpoint: 2026-10-15

A strict public offer validator and a once-only staging method were committed to the GitHub repository. The new test file has been updated to require the gateway host key from an independent trusted source. The developer's remote file writes were intermittently blocked, so the **new offer tests are not verified yet**. The preceding baseline of 35 tests remains separate from this increment.

Production registry, SSH credentials, port 10002 and the staged port 10003 were not changed. An offer still cannot activate a tunnel or grant privileges by itself. The next stage is to run the tests and implement an audited, narrow server-side provisioner rather than enabling arbitrary administrative commands.
