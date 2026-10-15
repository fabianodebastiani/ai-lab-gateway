#!/usr/bin/env bash
# WSL v2 pilot: connect/disconnect the *candidate* reverse tunnel on port 10003.
# No root, no systemd changes, no alteration to the existing 10002 tunnel.
# Production enrollment and host trust must already be independently approved.
set -Eeuo pipefail
umask 077

readonly HOME_SSH=/home/ai-gateway/.ssh
readonly V2_DIR="${HOME_SSH}/ai-lab-v2"
readonly PRIVATE_KEY="${V2_DIR}/tunnel-windows-wsl-ed25519"
readonly CONTROL_SOCKET="${V2_DIR}/candidate-control.sock"
readonly HOSTS="${HOME_SSH}/known_hosts"
readonly HOST=gateway.debasti.com
readonly USER=tunnel
readonly PORT=10003
readonly ACTION="${1:-}"
if [[ "${EUID}" == 0 || "$(id -un)" != "ai-gateway" ]]; then
  echo "Must run under non-root ai-gateway" >&2
  exit 77
fi
if [[ ! -d "$V2_DIR" || ! -f "$PRIVATE_KEY" || ! -f "$HOSTS" ]]; then
  echo "Candidate key or host-key trust is missing" >&2
  exit 77
fi
if [[ -L "$PRIVATE_KEY" || -L "$HOSTS" || ! -O "$PRIVATE_KEY" ]]; then
  echo "Candidate key owner/path unsafe" >&2
  exit 77
fi
if (( ($(stat -c %a "$PRIVATE_KEY") & 077) != 0 )); then
  # checked again below via mode bits; shell base-8 conversion is explicit.
  :
fi
mode=$(stat -c %a "$PRIVATE_KEY")
if [[ "$mode" != "600" ]]; then
  echo "Expected private key mode 0600" >&2
  exit 77
fi
ssh_opts=(
  -p 22 -i "$PRIVATE_KEY"
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$HOSTS"
  -o ExitOnForwardFailure=yes
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=3
  -S "$CONTROL_SOCKET"
)
case "$ACTION" in
  start)
    if [[ -e "$CONTROL_SOCKET" ]]; then
      if /usr/bin/ssh -O check "${ssh_opts[@]}" "${USER}@${HOST}" >/dev/null 2>&1; then
        echo "candidate tunnel already active"
        exit 0
      fi
      echo "Refusing to remove stale candidate socket automatically" >&2
      exit 77
    fi
    /usr/bin/ssh -M -f -N -T "${ssh_opts[@]}" \
      -R "127.0.0.1:${PORT}:127.0.0.1:22" "${USER}@${HOST}"
    echo "v2 candidate tunnel established on Oracle loopback port ${PORT}"
    ;;
  status)
    if [[ -S "$CONTROL_SOCKET" ]] &&
       /usr/bin/ssh -O check "${ssh_opts[@]}" "${USER}@${HOST}" >/dev/null 2>&1; then
      echo "candidate-active"
    else
      echo "candidate-disconnected"
      exit 1
    fi
    ;;
  stop)
    if [[ -S "$CONTROL_SOCKET" ]]; then
      /usr/bin/ssh -O exit "${ssh_opts[@]}" "${USER}@${HOST}" 2>/dev/null || true
      echo "candidate-disconnect-requested"
    else
      echo "candidate-not-connected"
    fi
    ;;
  *)
    echo "Usage: $0 {start|status|stop}" >&2
    exit 2
    ;;
esac
