#!/usr/bin/env python3
"""AI Lab Gateway human approval UI, separate from the OAuth/MCP principal.

Built entirely with Python stdlib. Two factors: a local password for the
short-lived browser session, and an independent TOTP code for each decision.
The UI user has no sudo permissions; root broker validates Unix peer UID.
"""
import argparse
import base64
import collections
import hashlib
import hmac
import html
import json
import os
import pwd
import secrets
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8001
SITE = "https://gateway.debasti.com"
BASE = "/approvals"
CREDENTIALS = Path("/etc/ai-lab-approval/credentials.json")
LAST_STEP_FILE = Path("/var/lib/ai-lab-approval/last_totp_step")
ADMIN_SOCKET = "/run/ai-lab-privilege-broker/approval.sock"
PAIRING_SOCKET = "/run/ai-lab-pairing/approver.sock"
SESSION_TTL = 900
LOGIN_TTL = 600
MAX_BODY = 8192
SESSIONS = {}
LOGIN_FORMS = {}
FAILURES = collections.deque(maxlen=1024)
MU = threading.RLock()
CSS = """
:root {color-scheme: light; font-family: system-ui, sans-serif}
body {margin:0;background:#f5f7fb;color:#19202a}
main {max-width:790px;margin:5vh auto;padding:0 20px}
section {background:white;border:1px solid #e1e6ec;border-radius:14px;
padding:25px;margin:16px 0;box-shadow:0 4px 14px #0b26400c}
h1 {font-size:1.55rem;margin:0 0 12px}
h2 {font-size:1.05rem;margin:0 0 12px}
p,.meta {line-height:1.5;color:#4a5664}
input {padding:10px;border:1px solid #bec8d4;border-radius:7px;
font:inherit;max-width:100%;box-sizing:border-box}
input[type=password] {width:100%;margin:8px 0 18px}
button {padding:9px 16px;border:0;border-radius:8px;cursor:pointer;
background:#1b5ca5;color:white;font-weight:600}
button.deny {background:#a03232}
button.outline {background:#f0f3f8;color:#19202a}
.actions {display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.error {color:#9f1a1a}
.ok {color:#126438}
code {overflow-wrap:anywhere}
small {color:#647183}
"""


def totp(secret_b32, at=None):
    now = int(time.time() if at is None else at)
    key = base64.b32decode(secret_b32, casefold=True)
    counter = now // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1_000_000:06d}"


def valid_totp(secret, entered, now=None):
    if not isinstance(entered, str) or len(entered) != 6 or not entered.isascii() or not entered.isdecimal():
        return None
    t = int(time.time() if now is None else now)
    for drift in (-1, 0, 1):
        if hmac.compare_digest(entered, totp(secret, t + drift * 30)):
            return (t // 30) + drift
    return None



def claim_totp_step(step):
    """Persistently reject reuse of a TOTP time window, even after restart."""
    if type(step) is not int:
        return False
    with MU:
        LAST_STEP_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if LAST_STEP_FILE.exists():
            previous = int(LAST_STEP_FILE.read_text(encoding="ascii").strip())
            if step <= previous:
                return False
        fd, tmp = tempfile.mkstemp(prefix=".totp-", dir=LAST_STEP_FILE.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(str(step) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, LAST_STEP_FILE)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return True


def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf8"), salt=salt,
                          n=1 << 14, r=8, p=1, dklen=32,
                          maxmem=64 * 1024 * 1024)


def read_credentials():
    if not CREDENTIALS.is_file():
        return None
    data = json.loads(CREDENTIALS.read_text(encoding="utf8"))
    if set(data) != {"salt", "password_hash", "totp_secret", "version"} or data["version"] != 1:
        raise ValueError("invalid approval credentials")
    return data


def verify_password(password, config):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        expected = bytes.fromhex(config["password_hash"])
        password = password.strip()
        return hmac.compare_digest(password_hash(password, bytes.fromhex(config["salt"])), expected)
    except (KeyError, ValueError):
        return False


def provision():
    if os.geteuid() != 0:
        raise PermissionError("enrollment requires root")
    if CREDENTIALS.exists():
        print("Credentials already configured. Refusing overwrite.", file=sys.stderr)
        return 77
    account = pwd.getpwnam("ai-lab-approver")
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    data = {"version": 1, "salt": salt.hex(),
            "password_hash": password_hash(password, salt).hex(),
            "totp_secret": secret}
    CREDENTIALS.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(CREDENTIALS.parent, 0, account.pw_gid)
    os.chmod(CREDENTIALS.parent, 0o750)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(CREDENTIALS, flags, 0o640)
    try:
        os.fchown(fd, 0, account.pw_gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(data, f)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        CREDENTIALS.unlink(missing_ok=True)
        raise
    print("\n=== AI LAB APPROVALS: CREDENCIAIS INICIAIS ===")
    print("Painel:", SITE + BASE)
    print("Senha:", password)
    print("Chave TOTP (Google Authenticator / Microsoft Authenticator): ", secret)
    print("Tipo: baseado em tempo (TOTP), SHA1, 6 dígitos, período 30 segundos")
    print("Guarde a senha e adicione a chave ao aplicativo autenticador.")
    print("Esses dados não serão mostrados novamente. Não os envie no chat.")
    return 0


def admin_rpc(message):
    request = (json.dumps(message, separators=(",", ":")) + "\n").encode()
    if len(request) > 8192:
        raise ValueError("admin message too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(ADMIN_SOCKET)
        sock.sendall(request)
        raw = bytearray()
        while not raw.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("broker disconnected")
            raw.extend(chunk)
            if len(raw) > 65536:
                raise ValueError("oversize broker reply")
    reply = json.loads(raw)
    if not isinstance(reply, dict):
        raise ValueError("invalid broker reply")
    return reply


def pairing_rpc(message):
    """Separate Unix credential boundary for device identity review.

    The web approval service has no permission to create pairing invitations,
    activate a device or change SSH keys. These are independent service roles.
    """
    request = (json.dumps(message, separators=(",", ":")) + "\n").encode()
    if len(request) > 8192:
        raise ValueError("oversize pairing review")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(PAIRING_SOCKET)
        sock.sendall(request)
        chunks = bytearray()
        while not chunks.endswith(b"\n"):
            block = sock.recv(4096)
            if not block:
                raise ConnectionError("pairing service disconnected")
            chunks.extend(block)
            if len(chunks) > 65536:
                raise ValueError("oversize pairing service response")
    reply = json.loads(chunks)
    if not isinstance(reply, dict):
        raise ValueError("invalid pairing response")
    return reply


def ssh_key_fingerprint(public_key):
    """Display a checkable SSH fingerprint for the independent human."""
    try:
        parts = public_key.strip().split()
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise ValueError("unexpected SSH key")
        blob = base64.b64decode(parts[1], validate=True)
        if not 40 <= len(blob) <= 100:
            raise ValueError("bad SSH key blob")
        return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    except (ValueError, TypeError, AttributeError):
        return "Chave SSH inválida"


def protected(text):
    return html.escape(str(text), quote=True)


def template(inner, title="Aprovações | AI Lab Gateway"):
    return ("<!doctype html><html lang='pt-BR'><head>"
            "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{protected(title)}</title><style>{CSS}</style></head>"
            f"<body><main><h1>AI Lab Gateway · Aprovações</h1>{inner}"
            "<p><small>As operações só podem ser executadas uma vez, após aprovação independente.</small></p>"
            "</main></body></html>").encode("utf8")


def failure_locked(client):
    now = time.monotonic()
    with MU:
        while FAILURES and now - FAILURES[0][0] > 300:
            FAILURES.popleft()
        local = sum(1 for t, ip in FAILURES if ip == client)
        return local >= 7 or len(FAILURES) >= 50


def register_failure(client):
    with MU:
        FAILURES.append((time.monotonic(), client))


def session_lookup(raw_cookie):
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie or "")
        token = cookie.get("ai_lab_approval")
        key = token.value if token else ""
    except Exception:
        return None
    with MU:
        entry = SESSIONS.get(key)
        if not entry or entry["expires_at"] < time.monotonic():
            SESSIONS.pop(key, None)
            return None
        return entry



def issue_login_csrf():
    """Bind a random login CSRF token to a separate Strict same-site cookie."""
    key, token = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    with MU:
        if len(LOGIN_FORMS) >= 1000:
            LOGIN_FORMS.clear()
        LOGIN_FORMS[key] = {"csrf": token, "expiry": time.monotonic() + LOGIN_TTL}
    return key, token


def verify_login_csrf(cookie_header, supplied):
    if not isinstance(supplied, str) or not supplied:
        return False
    try:
        jar = SimpleCookie()
        jar.load(cookie_header or "")
        morsel = jar.get("ai_lab_login")
        key = morsel.value if morsel is not None else ""
    except Exception:
        return False
    with MU:
        entry = LOGIN_FORMS.get(key)
        return bool(entry and entry["expiry"] >= time.monotonic()
                    and hmac.compare_digest(supplied, entry["csrf"]))


class ApprovalHandler(BaseHTTPRequestHandler):
    server_version = "AI-Lab-Approvals"
    sys_version = ""

    def _send(self, status, content=b"", cookie=None, redirect=None, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if redirect:
            self.send_header("Location", redirect)
        self.end_headers()
        if content:
            self.wfile.write(content)

    def _bad(self, message="Solicitação recusada.", status=403):
        self._send(status, template(f"<section><p class='error'>{protected(message)}</p><a href='{BASE}'>Voltar</a></section>"))

    def _origin_ok(self):
        """Validate transport basics; CSRF tokens protect browser form actions.

        Origin/Fetch Metadata may be altered or omitted by browser extensions
        or intermediaries. Each login form has an unguessable 10-minute CSRF
        token bound to a SameSite=Strict cookie; privileged decisions require
        an authenticated-session CSRF token and a separate TOTP code.
        """
        return (self.headers.get("Host") == "gateway.debasti.com"
                and self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                == "application/x-www-form-urlencoded")

    def _form(self):
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > MAX_BODY:
            raise ValueError("form size")
        data = self.rfile.read(int(length)).decode("utf8")
        pairs = urllib.parse.parse_qs(data, strict_parsing=True, keep_blank_values=True, max_num_fields=8)
        if any(len(v) != 1 for v in pairs.values()):
            raise ValueError("duplicate fields")
        return {k: v[0] for k, v in pairs.items()}

    def _pairing_page(self, session):
        try:
            reply = pairing_rpc({"action": "list"})
            if not reply.get("ok"):
                raise RuntimeError("pairing reviewer unavailable")
            requests = reply.get("requests", [])
            if not isinstance(requests, list):
                raise ValueError("unexpected review queue")
        except (ConnectionError, OSError, ValueError, RuntimeError):
            self._bad("O serviço de pareamento não está disponível.", 503)
            return
        blocks = [
            "<section><h2>Novos dispositivos</h2>"
            "<p>Confira a identidade e a impressão digital SSH no terminal "
            "do próprio dispositivo antes de aprovar. A aprovação autoriza "
            "o pareamento, mas não concede sudo ao MCP.</p>"
            f"<p><a href='{BASE}'>Voltar às operações administrativas</a></p></section>"
        ]
        for item in requests:
            rid = protected(item.get("request_id", ""))
            tunnel_fp = protected(ssh_key_fingerprint(item.get("tunnel_public_key", "")))
            host_fp = protected(ssh_key_fingerprint(item.get("ssh_host_public_key", "")))
            name = protected(item.get("device_name", ""))
            did = protected(item.get("device_id", ""))
            operator = protected(item.get("operator_subject", ""))
            persist = "Ligada" if item.get("persistent") is True else "Desligada"
            deadline = protected(time.strftime(
                "%Y-%m-%d %H:%M UTC", time.gmtime(item.get("approval_deadline", 0))
            ))
            blocks.append(
                f"<section><h2>{name}</h2>"
                f"<p class='meta'>ID: <code>{did}</code>"
                f"<br>Solicitante: <code>{operator}</code>"
                f"<br>Persistente: <strong>{persist}</strong>"
                f"<br>Acesso inicial: <strong>Restrito (sem sudo)</strong>"
                f"<br>Expira: {deadline}</p>"
                f"<p>Fingerprint SSH do host:<br><code>{host_fp}</code>"
                f"<br>Fingerprint da chave do túnel:<br><code>{tunnel_fp}</code></p>"
                f"<form action='{BASE}/pairing-decision' method='post'>"
                f"<input type='hidden' name='csrf' value='{protected(session['csrf'])}'>"
                f"<input type='hidden' name='request_id' value='{rid}'>"
                "<div class='actions'>"
                "<button name='decision' value='approve' type='submit'>Parear este dispositivo</button>"
                "<button name='decision' value='deny' class='deny' type='submit'>Rejeitar</button>"
                "</div></form></section>"
            )
        if not requests:
            blocks.append("<section><p>Nenhum dispositivo aguardando pareamento.</p></section>")
        self._send(200, template("".join(blocks), title="Pareamento | AI Lab Gateway"))

    def do_GET(self):
        if self.path == BASE + "/health":
            self._send(200, b"ok", content_type="text/plain; charset=utf-8")
            return
        if self.path not in (BASE, BASE + "/", BASE + "/pairing"):
            self._bad("Não encontrado", 404)
            return
        if self.headers.get("Host") != "gateway.debasti.com":
            self._bad("Host inválido")
            return
        if not CREDENTIALS.exists():
            self._send(503, template("<section><p>O painel aguarda a configuração das credenciais de aprovação.</p></section>"))
            return
        session = session_lookup(self.headers.get("Cookie"))
        if not session:
            login_cookie, csrf = issue_login_csrf()
            body = (f"<section><h2>Acesso administrativo</h2>"
                    f"<form action='{BASE}/login' method='post'>"
                    f"<input type='hidden' name='csrf' value='{protected(csrf)}'>"
                    "<label>Senha do aprovador<input type='password' name='password' required autocomplete='current-password'></label>"
                    "<button type='submit'>Entrar</button></form></section>")
            self._send(200, template(body),
                       cookie=f"ai_lab_login={login_cookie}; Path={BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age={LOGIN_TTL}")
            return
        if self.path == BASE + "/pairing":
            self._pairing_page(session)
            return
        try:
            result = admin_rpc({"action": "list"})
            if not result.get("ok"):
                raise RuntimeError("broker rejected listing")
            items = result.get("requests", [])
        except (ConnectionError, OSError, ValueError, RuntimeError):
            self._bad("Serviço de aprovação indisponível", 503)
            return
        blocks = [
            "<section><h2>Dispositivos</h2>"
            f"<p><a href='{BASE}/pairing'>Ver solicitações de pareamento</a></p>"
            "</section>"
        ]
        for item in items:
            rid = protected(item.get("request_id", ""))
            operation = protected(item.get("operation", ""))
            subject = protected(item.get("subject", ""))
            deadline = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(item["approval_deadline"]))
            csrf = protected(session["csrf"])
            blocks.append(
                f"<section><h2>{operation}</h2><p class='meta'>Dispositivo: "
                f"{protected(item.get('device_id'))} · Solicitante: <code>{subject}</code>"
                f"<br>Expira para aprovação: {protected(deadline)}"
                f"<br>Validade após aprovação: {int(item['ttl_seconds']) // 60} min</p>"
                f"<form action='{BASE}/decision' method='post'>"
                f"<input type='hidden' name='csrf' value='{csrf}'>"
                f"<input type='hidden' name='request_id' value='{rid}'>"
                "<label>Código do autenticador (6 dígitos)<input type='password' "
                "name='otp' inputmode='numeric' pattern='[0-9]{6}' maxlength='6' required></label>"
                "<div class='actions'><button name='decision' value='approve' type='submit'>Aprovar</button>"
                "<button name='decision' value='deny' class='deny' type='submit'>Negar</button></div>"
                "</form></section>"
            )
        if not blocks:
            blocks.append("<section><p>Nenhuma solicitação pendente.</p></section>")
        blocks.append(f"<form action='{BASE}/logout' method='post'>"
                      f"<input type='hidden' name='csrf' value='{protected(session['csrf'])}'>"
                      "<button class='outline'>Sair</button></form>")
        self._send(200, template("".join(blocks)))

    def do_POST(self):
        if self.path not in (BASE + "/login", BASE + "/decision", BASE + "/logout", BASE + "/pairing-decision"):
            self._bad("Rota do formulário não reconhecida")
            return
        if not self._origin_ok():
            if self.headers.get("Host") != "gateway.debasti.com":
                self._bad("Host da requisição não reconhecido")
            else:
                self._bad("Formato do formulário não reconhecido")
            return
        try:
            data = self._form()
        except (UnicodeError, ValueError):
            self._bad("Formulário inválido")
            return
        client = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0][:80]
        if self.path == BASE + "/login":
            if not verify_login_csrf(self.headers.get("Cookie"), data.get("csrf")):
                self._bad("Formulário expirado. Volte e atualize a página.")
                return
            if failure_locked(client):
                self._bad("Muitas tentativas. Aguarde alguns minutos.", 429)
                return
            config = read_credentials()
            if not config or not verify_password(data.get("password", ""), config):
                register_failure(client)
                self._bad("Credenciais inválidas")
                return
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(24)
            with MU:
                if len(SESSIONS) >= 200:
                    SESSIONS.clear()
                SESSIONS[token] = {"csrf": csrf, "expires_at": time.monotonic() + SESSION_TTL}
            self._send(303, cookie=f"ai_lab_approval={token}; Path={BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL}",
                       redirect=BASE)
            return
        session = session_lookup(self.headers.get("Cookie"))
        if not session or not hmac.compare_digest(data.get("csrf", ""), session["csrf"]):
            self._bad("Sessão inválida ou expirada")
            return
        if self.path == BASE + "/logout":
            with MU:
                cookie = SimpleCookie()
                cookie.load(self.headers.get("Cookie", ""))
                token = cookie.get("ai_lab_approval")
                if token:
                    SESSIONS.pop(token.value, None)
            self._send(303, cookie=f"ai_lab_approval=; Path={BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age=0", redirect=BASE)
            return
        if failure_locked(client):
            self._bad("Muitas tentativas. Aguarde alguns minutos.", 429)
            return
        rid = data.get("request_id", "")
        decision = data.get("decision", "")
        if not isinstance(rid, str) or len(rid) > 128 or decision not in ("approve", "deny"):
            self._bad("Decisão inválida")
            return
        if self.path == BASE + "/pairing-decision":
            # Device pairing is lower-risk than executing privileged root
            # commands and uses the independently authenticated browser
            # session + CSRF. OTP remains required for the root broker.
            try:
                reply = pairing_rpc({"action": decision, "request_id": rid})
            except (ConnectionError, OSError, ValueError):
                self._bad("Serviço de pareamento indisponível.", 503)
                return
            if not reply.get("ok"):
                self._bad("Pareamento não autorizado ou expirado.", 409)
                return
            self._send(303, redirect=BASE + "/pairing")
            return
        config = read_credentials()
        if not config:
            self._bad("Não configurado", 503)
            return
        step = valid_totp(config["totp_secret"], data.get("otp", ""))
        if step is None:
            register_failure(client)
            self._bad("Código do autenticador inválido")
            return
        try:
            if not claim_totp_step(step):
                self._bad("Código já utilizado. Aguarde o próximo código.")
                return
            reply = admin_rpc({"action": decision, "request_id": rid})
            if not reply.get("ok"):
                self._bad("Não foi possível processar: " + str(reply.get("error", "broker_error")), 409)
                return
        except (ConnectionError, OSError, ValueError):
            self._bad("Serviço indisponível", 503)
            return
        self._send(303, redirect=BASE)

    def log_message(self, format, *args):
        # Never log passwords, OTP values, session cookies or request bodies.
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enroll", action="store_true")
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    if args.enroll == args.serve:
        parser.error("choose --enroll or --serve")
    if args.enroll:
        return provision()
    if os.geteuid() == 0:
        raise PermissionError("web server must not run as root")
    os.umask(0o077)
    with ThreadingHTTPServer((HOST, PORT), ApprovalHandler) as server:
        server.daemon_threads = True
        server.serve_forever(poll_interval=0.25)
    return 0


if __name__ == "__main__":
    sys.exit(main())
