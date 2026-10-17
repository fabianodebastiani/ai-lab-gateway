#!/bin/sh
# AI Lab Gateway -- Linux device-code enrollment bootstrap (lab / pre-release).
# Source is pinned by Git commit AND SHA-256; only the nonroot Python CLI runs.
# Device-code HTTPS is online; SSH activation is NOT automated yet.
# This does not install, enable or authorize systemd, sshd, sudoers or SSH.
set -eu

RELEASE_COMMIT="909a66a7fa3654b9b7bf707f8c44a5f5ec39dcba"
CLIENT_SHA256="8c258ae6f23dc3bd00a9809443acfea9f1edf0861cf1b82ee3a01af8f0e7645b"
CLIENT_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${RELEASE_COMMIT}/scripts/device_code_pair_linux.py"
# Fixed, independently checksum-verified *local Linux* preparation helper.
# This helper sets up an ordinary, no-sudo ai-gateway account on fresh Ubuntu.
LOCAL_SETUP_COMMIT="b15054e57540414afc7faa9cf7442669c6dc0230"
LOCAL_SETUP_SHA256="1753c62d5dd9ce716ffc8a1582c9f16e603e17759a2353fe3b034aa9ee269454"
LOCAL_SETUP_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${LOCAL_SETUP_COMMIT}/scripts/ai_lab_prepare_linux_target.py"
# Non-root local CLI, pinned independently from the pairing client.
LOCAL_CLI_COMMIT="3c7d67334655338ffb0a003abf16a65fc963a150"
LOCAL_CLI_SHA256="4924cb0d0f1fdb9e361d4129f2d8c7045c9c1eaea093cb0ef66de9e489eb12af"
LOCAL_CLI_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${LOCAL_CLI_COMMIT}/scripts/ailab"


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

# This *public* Gateway SSH host identity was independently checked
# against Oracle's own host public key and the previously trusted WSL
# known_hosts entry. It is distributed with the versioned HTTPS bootstrap,
# never read unverified from the pending pairing offer.
gateway_pin="$directory/gateway-ssh-ed25519.pub"
printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIArkQEjGi6HfiJlMeKv8yv3xf6XripB4npdSSnYWFGjA' > "$gateway_pin"
chmod 600 "$gateway_pin"

# Every enrolled device must expose a non-sudo management account.
# A human runs THIS command locally, and the local OS sudo approval is
# required exactly once for initial OpenSSH/account preparation.
# Do NOT request this during --no-wait lab tests or an explicit loopback lab.
need_local_setup=yes
if [ "$(id -un)" = "ai-gateway" ]; then
    need_local_setup=no
else
    for arg do
        case "$arg" in
            --no-wait|--base-url) need_local_setup=no ;;
        esac
    done
fi

if [ "$need_local_setup" = no ]; then
    python3 "$client" --base-url https://gateway.debasti.com --trusted-gateway-host-key "$gateway_pin" "$@"
else
    if ! command -v sudo >/dev/null 2>&1; then
        printf '%s\n' "AI Lab: a configuração inicial requer sudo local no Linux." >&2
        exit 5
    fi
    helper="$directory/ai_lab_prepare_linux_target.py"
    printf '%s\n' "AI Lab: preparando usuário local Restrito; o Linux pode pedir sua senha sudo."
    curl --fail --location --silent --show-error \
         --proto '=https' --proto-redir '=https' --tlsv1.2 \
         --max-time 30 "$LOCAL_SETUP_URL" --output "$helper"
    if ! python3 -c '
import hashlib,sys
with open(sys.argv[1],"rb") as file:
    digest=hashlib.sha256(file.read()).hexdigest()
sys.exit(0 if digest == sys.argv[2] else 1)
' "$helper" "$LOCAL_SETUP_SHA256"; then
        printf '%s\n' "AI Lab: hash de preparação local incorreto." >&2
        exit 6
    fi
    sudo -- /usr/bin/python3 "$helper"
    home="$(getent passwd ai-gateway | awk -F: '{print $6}')"
    if [ "$home" != "/home/ai-gateway" ]; then
        printf '%s\n' "AI Lab: diretório inesperado para usuário Restrito." >&2
        exit 7
    fi
    target_id="$(id -u ai-gateway)"
    sudo -- install -d -o ai-gateway -g ai-gateway -m 0700 "$home/.cache/ai-lab-gateway"
    sudo -- install -o ai-gateway -g ai-gateway -m 0600 "$client" "$home/.cache/ai-lab-gateway/device_code_pair_linux.py"
    sudo -- install -o ai-gateway -g ai-gateway -m 0600 "$gateway_pin" "$home/.cache/ai-lab-gateway/gateway_host_key.pub"
    local_cli="$directory/ailab"
    curl --fail --location --silent --show-error \\
         --proto '=https' --proto-redir '=https' --tlsv1.2 \\
         --max-time 30 "$LOCAL_CLI_URL" --output "$local_cli"
    if ! python3 -c '
import hashlib,sys
with open(sys.argv[1],"rb") as file:
    digest=hashlib.sha256(file.read()).hexdigest()
sys.exit(0 if digest == sys.argv[2] else 1)
' "$local_cli" "$LOCAL_CLI_SHA256"; then
        printf '%s\\n' "AI Lab: hash do gestor local de conexão incorreto." >&2
        exit 8
    fi
    sudo -- install -d -o ai-gateway -g ai-gateway -m 0700 "$home/.local/bin"
    sudo -- install -o ai-gateway -g ai-gateway -m 0700 "$local_cli" "$home/.local/bin/ailab"
    printf '%s\\n' "AI Lab: gestor local verificado e instalado no usuário Restrito: $home/.local/bin/ailab"
    sudo -u ai-gateway -H -- env "XDG_RUNTIME_DIR=/run/user/$target_id" \
        /usr/bin/python3 "$home/.cache/ai-lab-gateway/device_code_pair_linux.py" \
        --base-url https://gateway.debasti.com \
        --trusted-gateway-host-key "$home/.cache/ai-lab-gateway/gateway_host_key.pub" "$@"
fi
