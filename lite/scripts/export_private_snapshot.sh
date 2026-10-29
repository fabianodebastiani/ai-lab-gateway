#!/usr/bin/env bash
# Export only versioned Lite source without carrying over the original Git history.
# Run from any directory within a clean clone of the original project.
set -euo pipefail

destination="${1:?Usage: export_private_snapshot.sh /path/to/new-empty-directory}"
repo_root="$(git rev-parse --show-toplevel)"
branch="$(git -C "$repo_root" branch --show-current)"
if [[ "$branch" != "gateway-lite" ]]; then
  echo "Refusing to export from branch '$branch' (expected gateway-lite)." >&2
  exit 1
fi

if [[ -e "$destination" ]]; then
  if [[ ! -d "$destination" || -n "$(ls -A "$destination")" ]]; then
    echo "Destination must be an empty directory." >&2
    exit 1
  fi
else
  mkdir -p "$destination"
fi

git -C "$repo_root" archive gateway-lite:lite | tar -x -C "$destination"
echo "Exported tracked Lite source to: $destination"
echo "No original .git history exported. Verify for secrets and create a PRIVATE remote BEFORE push."
echo "See docs/PRIVATE_REPO_MIGRATION.md."
