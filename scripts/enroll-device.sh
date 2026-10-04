#!/usr/bin/env bash
set -euo pipefail

# Prepare a Linux target for AI Lab Gateway enrollment.
# This script intentionally stops before installing any gateway-issued
# management key or tunnel authorization. Those are explicit enrollment steps.

TARGET_USER="${TARGET_USER:-ai-gateway}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (for example: sudo $0)" >&2
  exit 1
fi

if ! command -v ssh >/dev/null || ! command -v ssh-keygen >/dev/null; then
  echo "OpenSSH client is required" >&2
  exit 1
fi

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "${TARGET_USER}"
fi

install -d -m 700 -o "${TARGET_USER}" -g "${TARGET_USER}" "/home/${TARGET_USER}/.ssh"

TUNNEL_KEY="/home/${TARGET_USER}/.ssh/tunnel_ed25519"
if [[ ! -f "${TUNNEL_KEY}" ]]; then
  sudo -u "${TARGET_USER}" ssh-keygen -t ed25519 -N "" -f "${TUNNEL_KEY}"     -C "ai-lab-gateway tunnel"
fi

echo
echo "Target account prepared: ${TARGET_USER}"
echo "Tunnel public key (safe to copy to the gateway during enrollment):"
cat "${TUNNEL_KEY}.pub"
echo
echo "STOP: do not start a reverse tunnel yet."
echo "Next enrollment steps require an assigned device ID/port, pinned gateway"
echo "host key, and the gateway management public key."
