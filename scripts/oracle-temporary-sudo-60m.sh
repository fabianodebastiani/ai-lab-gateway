#!/usr/bin/env bash
# One-time Oracle admin bootstrap for a 60-minute lab maintenance window.
# Must be reviewed, pinned by SHA-256, and invoked as root by the human.
# No interaction with Auth0 credentials, MCP code, or SSH keys.
set -Eeuo pipefail
umask 077

if [[ "${EUID}" != "0" ]]; then
  echo "ERROR: run as root through the independent ubuntu recovery session" >&2
  exit 77
fi
for binary in /usr/sbin/visudo /usr/bin/systemctl /usr/bin/systemd-analyze /usr/bin/date /usr/bin/install; do
  [[ -x "$binary" ]] || { echo "Missing executable: $binary" >&2; exit 1; }
done
if ! /usr/bin/getent passwd ai-maintenance >/dev/null; then
  echo "ERROR: ai-maintenance does not exist" >&2; exit 1
fi

readonly RULE=/etc/sudoers.d/91-ai-lab-maintenance-60m
readonly UNIT=ai-lab-maintenance-60m-revoke
readonly SERVICE=/etc/systemd/system/${UNIT}.service
readonly TIMER=/etc/systemd/system/${UNIT}.timer
readonly TEMP_RULE=/etc/sudoers.d/.ai-lab-maintenance-60m-preflight

# Do not overwrite, modify, or accidentally remove existing privilege windows.
for candidate in "$RULE" "$SERVICE" "$TIMER" "$TEMP_RULE"; do
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    echo "ERROR: existing maintenance artifact: $candidate; inspect manually" >&2
    exit 1
  fi
done
/usr/sbin/visudo -c -f /etc/sudoers >/dev/null

# Validate the specific sudoers rule before touching any system service.
printf '%s\n' 'ai-maintenance ALL=(ALL:ALL) NOPASSWD: ALL' > "$TEMP_RULE"
chown root:root "$TEMP_RULE"
chmod 0440 "$TEMP_RULE"
if ! /usr/sbin/visudo -c -f "$TEMP_RULE" >/dev/null; then
  rm -f -- "$TEMP_RULE"
  echo "ERROR: candidate sudo rule is invalid" >&2
  exit 1
fi

deadline=$(/usr/bin/date -u -d '+60 minutes' '+%Y-%m-%d %H:%M:%S UTC')
/usr/bin/systemd-analyze calendar "$deadline" >/dev/null
armed=0
complete=0
cleanup() {
  rc=$?
  if (( complete == 0 )); then
    rm -f -- "$TEMP_RULE" "$RULE"
    if (( armed != 0 )); then
      /usr/bin/systemctl disable --now "${UNIT}.timer" >/dev/null 2>&1 || true
      rm -f -- "$TIMER" "$SERVICE"
      /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    echo "ABORTED: sudo window not granted (exit $rc)" >&2
  fi
}
trap cleanup EXIT

# The independent root-owned timer remains enabled over reboots. Persistent=true
# ensures that an elapsed deadline is serviced if the VM was powered off.
cat > "$SERVICE" <<EOF
[Unit]
Description=Revoke AI Lab temporary Oracle maintenance sudo
[Service]
Type=oneshot
ExecStart=/usr/bin/rm -f $RULE
EOF
cat > "$TIMER" <<EOF
[Unit]
Description=Hard deadline for AI Lab temporary Oracle maintenance sudo
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=${UNIT}.service
[Install]
WantedBy=timers.target
EOF
chown root:root "$SERVICE" "$TIMER"
chmod 0644 "$SERVICE" "$TIMER"
armed=1
/usr/bin/systemd-analyze verify "$SERVICE" "$TIMER"
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable --now "${UNIT}.timer"
/usr/bin/systemctl is-active --quiet "${UNIT}.timer"
next=$(/usr/bin/systemctl show --property=NextElapseUSecRealtime --value "${UNIT}.timer")
if [[ -z "$next" || "$next" == "n/a" ]]; then
  echo "ERROR: systemd timer has no next activation" >&2
  exit 1
fi

# Only enable wide sudo AFTER the expiry timer is valid and active.
mv -T -- "$TEMP_RULE" "$RULE"
/usr/sbin/visudo -c -f /etc/sudoers >/dev/null
complete=1
echo "MAINTENANCE_SUDO_ENABLED: ai-maintenance"
echo "AUTOMATIC_REVOCATION_UTC: $deadline"
echo "TIMER: ${UNIT}.timer ($next)"
echo "REVOKE_EARLY: sudo systemctl start ${UNIT}.service"
echo "NOTE: existing root processes are not killed by sudoers revocation"
