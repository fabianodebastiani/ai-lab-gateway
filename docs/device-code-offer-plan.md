# SSH offer protocol design

A device that passed user confirmation receives public connection metadata over its authenticated polling channel. The server must verify the approved request and use only a protected, allowlisted provisioner. The metadata includes the management public key, gateway SSH host public key and assigned loopback port. No private key is transferred. Production changes are not enabled by this document.
