#!/bin/sh
# AI Lab Gateway -- first Linux installer (restricted, lab pre-release).
# One local invocation prepares the non-admin ai-gateway account with LOCAL
# administrator sudo, verifies independently pinned artifacts, performs one-code
# pairing and starts a Restricted SSH tunnel after separate Auth0 confirmation.
# The protected per-operation root executor is installed DURING this local,
# sudo-authorized onboarding, AFTER identity pairing is independently confirmed.
# Installation is NOT a grant: every root operation needs an independent,
# Auth0-user/device-bound approval. No generic sudo is provisioned.
set -eu

RELEASE_COMMIT="909a66a7fa3654b9b7bf707f8c44a5f5ec39dcba"
CLIENT_SHA256="8c258ae6f23dc3bd00a9809443acfea9f1edf0861cf1b82ee3a01af8f0e7645b"
CLIENT_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${RELEASE_COMMIT}/scripts/device_code_pair_linux.py"
# Fixed, independently checksum-verified *local Linux* preparation helper.
# This helper sets up an ordinary, no-sudo ai-gateway account on fresh Ubuntu.
LOCAL_SETUP_COMMIT="ea8b8b2ba948a0a1c4c0be51002edb359b18ff57"
LOCAL_SETUP_SHA256="fe6e17929f69e74357dea9800264066d24d98d566c939538b3614c4494d07f1c"
LOCAL_SETUP_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${LOCAL_SETUP_COMMIT}/scripts/ai_lab_prepare_linux_target.py"
# Non-root local CLI, pinned independently from the pairing client.
LOCAL_CLI_COMMIT="3c7d67334655338ffb0a003abf16a65fc963a150"
LOCAL_CLI_SHA256="4924cb0d0f1fdb9e361d4129f2d8c7045c9c1eaea093cb0ef66de9e489eb12af"
LOCAL_CLI_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${LOCAL_CLI_COMMIT}/scripts/ailab"

# Reviewed one-use root executor and installer from PR #10, immutable by SHA.
# The issuer PUBLIC key and its fingerprint come from the independently
# operator-verified Gateway signer, NOT an untrusted pairing response.
PRIVEXEC_COMMIT="930b288f5cf661e2883a68e032f27ffecc78790b"
PRIVEXEC_INSTALL_SHA256="cef19bc7bdcaf24d17051eb2d47bc5b3124b931ade0f08d6143d8e75a795788b"
PRIVEXEC_EXEC_SHA256="d94660a4e1a925d50fd3bd2fda02408cf5300458ad0ddd85498ba4203bdea632"
PRIVEXEC_INSTALL_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${PRIVEXEC_COMMIT}/scripts/install_target_privexec.py"
PRIVEXEC_EXEC_URL="https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/${PRIVEXEC_COMMIT}/scripts/ai-lab-target-privexec"
ISSUER_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGVKpXLqOIGRXuYF9Z1T7HZ9Xv+CpH1b00zhTHSzckp"
ISSUER_FINGERPRINT="SHA256:r0E6FcgCHXL0/bOarLK9gP4QQK6BFDaDiUDfUCBXW6E"


if [ "$(uname -s)" != "Linux" ]; then
    printf '%s\n' "AI Lab: este instalador requer Linux." >&2
    exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "AI Lab: execute como usuário comum, SEM sudo." >&2
    exit 2
fi
# Read-only local system preflight. Explicit mode: never contacts Gateway,
# downloads code, prompts for sudo or creates any files.
if [ "${1:-}" = "--check" ]; then
    if [ "$#" -ne 1 ]; then
        printf '%s\n' "AI Lab: --check não aceita outros argumentos." >&2
        exit 2
    fi
    for prerequisite in python3 ssh-keygen mktemp sudo id getent; do
        if ! command -v "$prerequisite" >/dev/null 2>&1; then
            printf 'AI Lab: falta %s.\n' "$prerequisite" >&2
            exit 2
        fi
    done
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        printf '%s\n' "AI Lab: falta curl ou wget para download HTTPS." >&2
        exit 2
    fi
    if ! python3 -c 'import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
        printf '%s\n' "AI Lab: Python 3.10+ é necessário." >&2
        exit 2
    fi
    if [ ! -f /etc/debian_version ] || [ ! -d /run/systemd/system ]; then
        printf '%s\n' "AI Lab: esta versão automática exige Ubuntu/Debian com systemd." >&2
        exit 2
    fi
    printf '%s\n' "AI_LAB_INSTALL_PRECHECK_OK"
    printf '%s\n' "Plano: sudo LOCAL para preparar sshd e ai-gateway; baixar e verificar artefatos; parear por código/Auth0; instalar executor root protegido após aprovação do dispositivo. Nenhum sudo remoto/genérico ou aprovação root é concedido."
    exit 0
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

# One TLS-only downloader for all pinned components; wget-only systems
# must not fall back to an unverified HTTP request.
download() {
    source_url="$1"
    destination="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error \
             --proto '=https' --proto-redir '=https' --tlsv1.2 \
             --max-time 30 "$source_url" --output "$destination"
    else
        wget --quiet --https-only --timeout=30 \
             --output-document="$destination" "$source_url"
    fi
}

directory="$(mktemp -d "${TMPDIR:-/tmp}/ai-lab-pair.XXXXXXXX")"
chmod 700 "$directory"
trap 'rm -rf -- "$directory"' 0
trap 'exit 130' 1 2 3 15

sha_check() {
    if ! python3 -c '
import hashlib,sys
with open(sys.argv[1],"rb") as file:
    digest=hashlib.sha256(file.read()).hexdigest()
sys.exit(0 if digest == sys.argv[2] else 1)
' "$1" "$2"; then
        printf '%s\n' "AI Lab: checksum inválido no componente root. Instalação interrompida." >&2
        exit 12
    fi
}

prepare_privexec() {
    if [ "$(id -un)" = "ai-gateway" ]; then
        printf '%s\n' "AI Lab: executor requer sudo do administrador Linux original." >&2
        exit 11
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        printf '%s\n' "AI Lab: sudo local indisponível; executor permanece ausente." >&2
        exit 11
    fi
    exec_installer="$directory/install_target_privexec.py"
    exec_source="$directory/ai-lab-target-privexec"
    pubkey="$directory/issuer-public-key.pub"
    download "$PRIVEXEC_INSTALL_URL" "$exec_installer"
    sha_check "$exec_installer" "$PRIVEXEC_INSTALL_SHA256"
    download "$PRIVEXEC_EXEC_URL" "$exec_source"
    sha_check "$exec_source" "$PRIVEXEC_EXEC_SHA256"
    (umask 077; printf '%s\n' "$ISSUER_PUBLIC_KEY" > "$pubkey")
    # Only after real pairing, the local account owns the persisted device id.
    # A fresh sudo prompt may be needed if the code approval took > sudo TTL.
    device_id="$(sudo -- /usr/bin/cat /home/ai-gateway/.ssh/ai-lab-device-code/device-id)"
    if [ -z "$device_id" ]; then
        printf '%s\n' "AI Lab: identidade pareada ausente; root não instalado." >&2
        exit 12
    fi
    printf '%s\n' "AI Lab: verificando executor limitado e chave PÚBLICA de aprovação."
    sudo -- /usr/bin/python3 -I "$exec_installer" \
        --check --device-id "$device_id" \
        --issuer-public-key "$pubkey" \
        --issuer-fingerprint "$ISSUER_FINGERPRINT" \
        --executor-source "$exec_source"
    sudo -- /usr/bin/python3 -I "$exec_installer" \
        --apply --device-id "$device_id" \
        --issuer-public-key "$pubkey" \
        --issuer-fingerprint "$ISSUER_FINGERPRINT" \
        --executor-source "$exec_source"
    if sudo -n -u ai-gateway -H -- sudo -n /usr/bin/id -u >/dev/null 2>&1; then
        printf '%s\n' "AI Lab: ERRO DE SEGURANÇA: sudo genérico disponível!" >&2
        exit 13
    fi
    printf '%s\n' "AI_LAB_PRIVEXEC_INSTALLED_DENY_ALL: somente autorização assinada, individual e de uso único."
}

# Existing Linux device: upgrade protected executor without re-pairing,
# replacing SSH identities or overwriting the operator's ailab wrapper.
if [ "${1:-}" = "--upgrade-sudo" ]; then
    if [ "$#" -ne 1 ]; then
        printf '%s\n' "AI Lab: --upgrade-sudo não recebe parâmetros." >&2
        exit 2
    fi
    prepare_privexec
    exit 0
fi
client="$directory/device_code_pair_linux.py"

printf '%s\n' "AI Lab: baixando cliente de versão fixa (Git ${RELEASE_COMMIT})."
download "$CLIENT_URL" "$client"

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
    download "$LOCAL_SETUP_URL" "$helper"
    if ! python3 -c '
import hashlib,sys
with open(sys.argv[1],"rb") as file:
    digest=hashlib.sha256(file.read()).hexdigest()
sys.exit(0 if digest == sys.argv[2] else 1)
' "$helper" "$LOCAL_SETUP_SHA256"; then
        printf '%s\n' "AI Lab: hash de preparação local incorreto." >&2
        exit 6
    fi
    # Verify every downloaded artifact BEFORE any privileged local mutation.
    local_cli="$directory/ailab"
    download "$LOCAL_CLI_URL" "$local_cli"
    if ! python3 -c '
import hashlib,sys
with open(sys.argv[1],"rb") as file:
    digest=hashlib.sha256(file.read()).hexdigest()
sys.exit(0 if digest == sys.argv[2] else 1)
' "$local_cli" "$LOCAL_CLI_SHA256"; then
        printf '%s\n' "AI Lab: hash do gestor local de conexão incorreto." >&2
        exit 8
    fi
    # Reject obvious human shortcut conflicts before creating a Linux account.
    if [ -L "$HOME/.local" ] || [ -L "$HOME/.local/bin" ]; then
        printf '%s\n' "AI Lab: diretório local é link simbólico; não vou instalar o atalho." >&2
        exit 9
    fi
    if [ -e "$HOME/.local/bin/ailab" ] || [ -L "$HOME/.local/bin/ailab" ]; then
        printf '%s\n' "AI Lab: atalho ailab existente. Não alterarei o Linux até revisar o conflito." >&2
        exit 9
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
    sudo -- install -d -o ai-gateway -g ai-gateway -m 0700 "$home/.local/bin"
    sudo -- install -o ai-gateway -g ai-gateway -m 0700 "$local_cli" "$home/.local/bin/ailab"
    printf '%s\n' "AI Lab: gestor local verificado e instalado no usuário Restrito: $home/.local/bin/ailab"
    sudo -u ai-gateway -H -- env "XDG_RUNTIME_DIR=/run/user/$target_id" \
        /usr/bin/python3 "$home/.cache/ai-lab-gateway/device_code_pair_linux.py" \
        --base-url https://gateway.debasti.com \
        --trusted-gateway-host-key "$home/.cache/ai-lab-gateway/gateway_host_key.pub" "$@"
    # Pairing has completed, but does NOT constitute authorization for root.
    # Original local admin explicitly authorizes this installation; separate
    # human approvals are still required for every privileged operation.
    prepare_privexec
    # Only publish the human convenience shortcut after successful pairing.
    # Human-facing wrapper in the ORIGINAL user's own home. This wrapper
    # ONLY drops to the pre-existing, independently paired ai-gateway identity
    # and accepts a small fixed local command set. No privileged shell.
    wrapper="$directory/ailab-human-wrapper"
    cat > "$wrapper" <<'AI_LAB_HUMAN_CLI_WRAPPER'
#!/bin/sh
set -eu
case "$#:${1:-}:${2:-}" in
    1:status:|1:connect:|1:disconnect:|2:persistent:on|2:persistent:off) ;;
    *) printf '%s\n' 'AI Lab: uso: ailab status|connect|disconnect|persistent on|persistent off' >&2; exit 2 ;;
esac
if ! command -v sudo >/dev/null 2>&1; then
    printf '%s\n' 'AI Lab: sudo local é necessário para alternar para o usuário Restrito.' >&2
    exit 3
fi
if [ "$(id -un)" = "ai-gateway" ]; then
    exec /usr/bin/python3 /home/ai-gateway/.local/bin/ailab "$@"
fi
managed_uid="$(id -u ai-gateway)"
exec sudo -u ai-gateway -H -- env "XDG_RUNTIME_DIR=/run/user/$managed_uid" \
    /usr/bin/python3 /home/ai-gateway/.local/bin/ailab "$@"
AI_LAB_HUMAN_CLI_WRAPPER
    chmod 700 "$wrapper"
    # Never replace a pre-existing executable in a human's home.
    if [ -L "$HOME/.local" ] || [ -L "$HOME/.local/bin" ]; then
        printf '%s\n' "AI Lab: diretório local é link simbólico; não vou instalar o atalho." >&2
        exit 9
    fi
    (umask 077; mkdir -p -- "$HOME/.local/bin")
    shortcut="$HOME/.local/bin/ailab"
    if [ -e "$shortcut" ] || [ -L "$shortcut" ]; then
        if [ -L "$shortcut" ] || ! cmp -s "$wrapper" "$shortcut"; then
            printf '%s\n' "AI Lab: já existe um ailab diferente; não vou sobrescrever." >&2
            exit 9
        fi
    else
        install -m 0700 "$wrapper" "$shortcut"
    fi
    printf '%s\n' "AI Lab: comando local instalado: $shortcut"
    printf '%s\n' "AI Lab: depois do pareamento use esse comando com status, connect, disconnect ou persistent on/off."
    printf '%s\n' "AI Lab: executor root instalado, NEGADO por padrão. Sudo requer aprovação humana independente via Gateway."
fi
