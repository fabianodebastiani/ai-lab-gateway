#!/bin/sh
# AI Lab Gateway -- Linux device-code enrollment bootstrap (lab / pre-release).
# Source is pinned by Git commit AND SHA-256; only the nonroot Python CLI runs.
# This does not install, enable or authorize systemd, sshd, sudoers or SSH.
# Production Gateway endpoint /pairing/device/start is NOT deployed yet.
set -eu

RELEASE_COMMIT="536f5e1ce5fa885d9aa1d757182a01c10d751ae5"
CLIENT_SHA256="c25b3ad332c439e49aa9946cd0fd1330c68b979ed34237a6665e88627f8594d3"
CLIENT_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${RELEASE_COMMIT}/scripts/device_code_pair_linux.py"

if [ "$(uname -s)" != "Linux" ]; then
    printf '%s\n' "AI Lab: este instalador requer Linux." >&2
    exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "AI Lab: execute como usuário comum, SEM sudo." >&2
    exit 2
fi
for cmd in python3 ssh-keygen mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'AI Lab: falta %s. Instale Python 3.10+ e OpenSSH client antes de continuar.\n' "$cmd" >&2
        exit 2
    fi
done
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    printf '%s\n' 'AI Lab: curl ou wget é necessário para baixar o cliente.' >&2
    exit 2
fi
if ! python3 -c 'import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
    printf '%s\n' "AI Lab: Python 3.10+ é necessário." >&2
    exit 2
fi

directory="$(mktemp -d "${TMPDIR:-/tmp}/ai-lab-pair.XXXXXXXX")"
chmod 700 "$directory"
trap 'rm -rf -- "$directory"' 0
trap 'exit 130' 1 2 3 15
client="$directory/device_code_pair_linux.py"

printf '%s\n' "AI Lab: baixando cliente de versão fixa (Git ${RELEASE_COMMIT})."
if command -v curl >/dev/null 2>&1; then
    curl --fail --location --silent --show-error \
         --proto '=https' --proto-redir '=https' --tlsv1.2 \
         --max-time 30 "$CLIENT_URL" --output "$client"
else
    wget --quiet --https-only --timeout=30 --output-document="$client" "$CLIENT_URL"
fi

# The digest is embedded in this TLS-delivered bootstrap, never taken from
# the downloaded artifact or a mutable, unsigned remote manifest.
if ! python3 -c '
import hashlib,sys
with open(sys.argv[1],"rb") as file:
    digest=hashlib.sha256(file.read()).hexdigest()
sys.exit(0 if digest == sys.argv[2] else 1)
' "$client" "$CLIENT_SHA256"; then
    printf '%s\n' "AI Lab: HASH INCORRETO; cliente não será executado." >&2
    exit 3
fi
printf '%s\n' "AI Lab: hash SHA-256 validado. Executando sem privilégios administrativos."

# Production HTTPS will be the default only once its new device API is live.
# The CLI currently requires --base-url; lab may use http://127.0.0.1:PORT.
python3 "$client" "$@"
