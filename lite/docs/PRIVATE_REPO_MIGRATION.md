# First private repository release checklist

## Decision

The original AI Lab Gateway remains PUBLIC for now. Development of Lite occurs under `gateway-lite/lite/` in that public repository until it is ready to be moved.

**Important:** code committed in this PUBLIC branch is visible to everyone, regardless of the future visibility of the standalone repository. No runtime configurations, credentials or device details may be committed here.

## Creating the standalone Lite repository

1. In GitHub, create a NEW EMPTY repository named `ai-lab-gateway-lite`, set **Private** in the creation form, and confirm visibility before the first push. Do not create it publicly and convert it afterward.
2. Invite only specific GitHub collaborators. Access to source code does not automatically authorize anyone to use the running MCP.
3. From a trusted local clone of the original repository, run `./lite/scripts/export_private_snapshot.sh /path/to/new-empty-directory` on the `gateway-lite` branch to export ONLY the files in `lite/`. This exports a CLEAN source snapshot, not the original Git history.
4. Review the exported directory with a secret scanner (for example gitleaks or GitHub secret scanning) and manually inspect env/config examples, SSH keys and domain references.
5. Inside the exported directory, initialize a NEW Git repository, commit the snapshot, add the new PRIVATE GitHub remote, and push only after verifying the remote is private.
6. Configure private-repository GitHub Actions and collaborator access policies. Never publish GitHub Actions artifacts containing live database, SSH credentials or access tokens.
7. After the separate repository passes tests, the source under the old public branch may be retired; this does not undo its prior public exposure.

## No dependency on public GitHub for the Lite runtime

The Lite has no anonymous download/bootstrap system. Install it by authenticated checkout (or release artifacts distributed through an authorized private channel) on the separate Oracle Lite VM.

Do NOT place OAuth client secrets, SSH private keys, real user `sub` values, runtime SQLite databases or private network inventories inside Git. Deployment secrets belong under protected paths on the VM.

The original Gateway's public device installer is a separate project dependency and **must remain functional** while that repository remains public.

## Auth0 test phase

Use the EXISTING Auth0 tenant, with a NEW Lite MCP API audience and a separate Lite web-app client. For isolated functional tests, the Auth0-provided shared Google social development credentials can be used. Before handling regular operational users, configure a dedicated Google Cloud OAuth app and update Auth0's Google social connection. Never change the original Gateway's API audience or break its Google login flow.
