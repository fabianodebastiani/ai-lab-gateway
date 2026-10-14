#!/usr/bin/env bash
# AI Lab Gateway v2: safe local systemd connection control.
# Operations affect ONLY the explicitly named AI Lab tunnel service.
# They do NOT enroll a device, change SSH keys, or grant sudo to the MCP.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: device-connection.sh <connect|disconnect|persistent|on-demand|status> <unit>

  connect     Start the tunnel now; leave its boot preference unchanged.
  disconnect  Stop the tunnel now; leave its boot preference unchanged.
  persistent  Enable systemd auto-start AND start the tunnel now.
  on-demand   Disable systemd auto-start; do not stop an active connection.
  status      Show running state and configured connection mode.

Example WSL:
  sudo device-connection.sh connect ai-lab-wsl-tunnel.service
  sudo device-connection.sh disconnect ai-lab-wsl-tunnel.service
  device-connection.sh status ai-lab-wsl-tunnel.service

Example always-on Raspberry:
  sudo device-connection.sh persistent ai-lab-reverse-tunnel.service

NOTE: systemd on WSL only starts when the WSL distribution itself starts.
      Persistent mode does not power on a sleeping/closed Windows laptop.
EOF
}
if [[ $# -ne 2 ]]; then usage >&2; exit 2; fi
action="$1"
unit="$2"

# Do not allow arbitrary host services to be targeted by this helper.
if [[ ! "$unit" =~ ^ai-lab-[a-z0-9-]+-tunnel[.]service$ ]]; then
  printf 'Unsupported service name: %s\n' "$unit" >&2
  exit 2
fi

if [[ "$action" != "status" && "$action" != "connect" &&
      "$action" != "disconnect" && "$action" != "persistent" &&
      "$action" != "on-demand" ]]; then
  usage >&2; exit 2
fi

if [[ "$action" != "status" && "$EUID" -ne 0 ]]; then
  echo "Run state-changing operations with local administrator sudo." >&2
  exit 1
fi

if ! /usr/bin/systemctl cat "$unit" >/dev/null 2>&1; then
  printf 'Tunnel unit not found: %s\n' "$unit" >&2
  exit 3
fi

case "$action" in
  connect)
    /usr/bin/systemctl start "$unit"
    ;;
  disconnect)
    /usr/bin/systemctl stop "$unit"
    ;;
  persistent)
    /usr/bin/systemctl enable --now "$unit"
    ;;
  on-demand)
    # Disable auto-start but preserve the current live connection.
    /usr/bin/systemctl disable "$unit"
    ;;
esac

active=$(/usr/bin/systemctl is-active "$unit" 2>/dev/null || true)
enabled=$(/usr/bin/systemctl is-enabled "$unit" 2>/dev/null || true)
case "$enabled" in
  enabled|enabled-runtime|linked|linked-runtime) mode="persistent" ;;
  disabled|static|indirect|masked|not-found|"") mode="on-demand" ;;
  *) mode="on-demand" ;;
esac
printf 'unit=%s\nmode=%s\nactive=%s\nsystemd-enabled=%s\n' \
  "$unit" "$mode" "$active" "$enabled"
