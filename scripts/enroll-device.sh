#!/usr/bin/env bash
set -euo pipefail

# Prepare a Linux target for AI Lab Gateway enrollment.
# This script intentionally stops before installing gateway-issued management
# trust, pinning the gateway host key, or starting the reverse tunnel.

TARGET_USER="${TARGET_USER:-ai-gateway}"
DEVICE_ID="${DEVICE_ID:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (for example: sudo $0)" >&2
  exit 1
fi

for command in ssh ssh-keygen sshd; do
  if ! command -v "${command}" >/dev/null; then
    echo "OpenSSH client and server are required (missing: ${command})" >&2
    exit 1
  fi
done

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "${TARGET_USER}"
fi

TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
if [[ -z "${TARGET_HOME}" ]]; then
  echo "Could not determine home directory for ${TARGET_USER}" >&2
  exit 1
fi

install -d -m 700 -o "${TARGET_USER}" -g "${TARGET_USER}" "${TARGET_HOME}/.ssh"

TUNNEL_KEY="${TARGET_HOME}/.ssh/tunnel_ed25519"
if [[ ! -f "${TUNNEL_KEY}" ]]; then
  KEY_COMMENT="${DEVICE_ID:+${DEVICE_ID} }tunnel"
  sudo -u "${TARGET_USER}" ssh-keygen -t ed25519 -N "" -f "${TUNNEL_KEY}" -C "${KEY_COMMENT}"
fi

chmod 600 "${TUNNEL_KEY}"
chmod 644 "${TUNNEL_KEY}.pub"
chown "${TARGET_USER}:${TARGET_USER}" "${TUNNEL_KEY}" "${TUNNEL_KEY}.pub"

echo
echo "Target account prepared: ${TARGET_USER}"
echo "Tunnel public key (safe to copy to the gateway during enrollment):"
cat "${TUNNEL_KEY}.pub"
echo
echo "STOP: do not start a reverse tunnel yet."
echo "Next enrollment steps require an assigned device ID/port, a deliberately"
echo "pinned gateway host key, a per-key permitlisten restriction on the gateway,"
echo "and the gateway management public key installed on this target."
