"""Minimal Auth0 OIDC administrative console; no shared password or JS required.

The panel is separate from MCP authentication and does not grant MCP access.
Every mutation requires an independently verified administrator subject and CSRF.
"""
import html
import os
from secrets import token_urlsafe
from urllib.parse import parse_qs

from authlib.integrations.starlette_client import OAuth
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from starlette.routing import Route

from .ssh_exec import execute
from .store import ACTIONS, Device, Store

CSS = """<style>
body{font:15px system-ui,Arial;max-width:1100px;margin:35px auto;padding:0 18px;color:#18232c;background:#f6f8fa}
header{display:flex;justify-content:space-between;align-items:center}
section{background:white;border:1px solid #dae2e8;border-radius:12px;padding:20px;margin:18px 0}
h1{font-size:24px}h2{font-size:19px}input,select,button{padding:8px;margin:4px}
table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #eee;text-align:left}
button{background:#075e55;color:white;border:0;border-radius:5px;cursor:pointer}
small{color:#52606d}.danger{color:#a83232}
</style>"""


def _e(value):
    return html.escape(str(value), quote=True)


def _page(title, body):
    return HTMLResponse(
        '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>' + _e(title) + '</title>' + CSS + '</head><body>' + body + '</body></html>',
        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                 "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
                 "X-Content-Type-Options": "nosniff",
                 "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
                 "X-Frame-Options": "DENY"},
    )


def create_panel(store: Store) -> Starlette:
    base_url = os.environ["LITE_BASE_URL"].rstrip("/")
    if not base_url.startswith("https://") or "/" in base_url[8:]:
        raise ValueError("LITE_BASE_URL must be an HTTPS origin")
    session_secret = os.environ["LITE_SESSION_SECRET"]
    if len(session_secret) < 32:
        raise ValueError("LITE_SESSION_SECRET must be at least 32 characters")
    client_id = os.environ["LITE_WEB_CLIENT_ID"]
    client_secret = os.environ["LITE_WEB_CLIENT_SECRET"]
    issuer = os.environ["LITE_OAUTH_ISSUER"].rstrip("/") + "/"
    admin_subjects = {s.strip() for s in os.environ.get("LITE_ADMIN_SUBJECTS", "").split(",") if s.strip()}
    if not admin_subjects:
        raise ValueError("LITE_ADMIN_SUBJECTS must be provisioned before exposing admin UI")
    oauth = OAuth()
    oauth.register(
        name="auth0", client_id=client_id, client_secret=client_secret,
        server_metadata_url=issuer + ".well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

    def current_user(request: Request):
        subject = request.session.get("sub")
        return subject if isinstance(subject, str) and subject else None

    def csrf(request: Request):
        if "csrf" not in request.session:
            request.session["csrf"] = token_urlsafe(32)
        return request.session["csrf"]

    def assert_admin(request: Request):
        if current_user(request) not in admin_subjects:
            raise PermissionError("administrator permission required")

    async def post_form(request: Request):
        assert_admin(request)
        if request.headers.get("origin") != base_url:
            raise PermissionError("invalid request origin")
        if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
            raise ValueError("unsupported form content type")
        body = await request.body()
        if len(body) > 8192:
            raise ValueError("form is too large")
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=24)
        fields = {key: values[-1] for key, values in parsed.items()}
        if not fields.get("csrf") or fields["csrf"] != request.session.get("csrf"):
            raise PermissionError("invalid CSRF")
        return fields

    def redirect_admin():
        return RedirectResponse("/admin", status_code=303)

    async def landing(request: Request):
        return RedirectResponse("/admin", status_code=303)

    async def login(request: Request):
        return await oauth.auth0.authorize_redirect(
            request, base_url + "/auth/callback", code_challenge_method="S256")

    async def callback(request: Request):
        token = await oauth.auth0.authorize_access_token(request)
        info = token.get("userinfo")  # validated Auth0 OIDC ID token
        if not info or not info.get("sub"):
            return PlainTextResponse("OIDC identity unavailable", status_code=403)
        request.session.clear()
        subject = str(info["sub"])
        request.session["sub"] = subject
        request.session["email"] = str(info.get("email", ""))
        request.session["display_name"] = str(info.get("name", ""))
        store.record_user(subject, request.session["email"], request.session["display_name"])
        return redirect_admin()

    async def logout(request: Request):
        if request.headers.get("origin") != base_url:
            return PlainTextResponse("invalid origin", status_code=403)
        form = parse_qs((await request.body()).decode("utf-8"))
        if form.get("csrf", [""])[-1] != request.session.get("csrf"):
            return PlainTextResponse("invalid CSRF", status_code=403)
        request.session.clear()
        return RedirectResponse("/admin", status_code=303)

    async def admin(request: Request):
        subject = current_user(request)
        if not subject:
            return _page("Gateway Lite", '<h1>AI Lab Gateway Lite</h1><p>Administração protegida por Auth0.</p>'
                         '<a href="/auth/login">Entrar com Google via Auth0</a>')
        if subject not in admin_subjects:
            return _page("Acesso pendente", '<h1>Login confirmado</h1>'
                         '<p>Sua conta ainda não tem direitos de administração ou acesso MCP.</p>'
                         '<p>Solicite autorização ao administrador.</p>')
        token = _e(csrf(request))
        logout_form = ('<form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="'
                       + token + '"><button>Sair</button></form>')
        out = ['<header><h1>AI Lab Gateway Lite</h1>' + logout_form + '</header>',
               '<p>Administrador: ' + _e(request.session.get("email") or subject) + '</p>']
        users = store.list_users()
        devices = store.list_devices()
        grants = {(g["subject"], g["device_id"], g["action"]) for g in store.list_grants()}

        out.append('<section><h2>Usuários autenticados</h2><table><tr><th>Conta</th><th>Identificador Auth0</th></tr>')
        for u in users:
            out.append('<tr><td>' + _e(u["display_name"] or u["email"] or "(sem nome)") +
                       '</td><td><small>' + _e(u["subject"]) + '</small></td></tr>')
        out.append('</table><small>Novo usuário precisa fazer login antes de receber permissões.</small></section>')

        out.append('<section><h2>Dispositivos</h2><table>'
                   '<tr><th>Nome</th><th>IP WireGuard</th><th>SSH</th><th>Ativo</th><th>Teste</th></tr>')
        for d in devices:
            out.append('<tr><td>' + _e(d.name) + '</td><td>' + _e(d.host) + ':' + str(d.port) +
                       '</td><td>' + _e(d.ssh_user) + '</td><td>' +
                       ("Sim" if d.enabled else "Não") +
                       '</td><td><a href="/admin/check?device_id=' + _e(d.id) +
                       '">Verificar</a></td></tr>')
        out.append('</table><h3>Adicionar / atualizar</h3><form method="post" action="/admin/device">'
                   '<input type="hidden" name="csrf" value="' + token + '">'
                   '<input required name="id" placeholder="ID único (ex: linux-lab)">'
                   '<input required name="name" placeholder="Nome amigável">'
                   '<input required name="host" placeholder="IP WireGuard">'
                   '<input required name="port" type="number" min="1" max="65535" value="22">'
                   '<input required name="ssh_user" placeholder="Usuário SSH">'
                   '<input required name="key_name" placeholder="Nome da chave SSH">'
                   '<label><input type="checkbox" name="enabled" checked>Ativo</label>'
                   '<button>Salvar dispositivo</button></form>'
                   '<small>Chaves privadas e host keys são instaladas fora do painel, diretamente na VM.</small></section>')

        out.append('<section><h2>Permissões por usuário e dispositivo</h2><table>'
                   '<tr><th>Usuário</th><th>Dispositivo</th><th>Ação</th><th>Permissão</th></tr>')
        for u in users:
            for d in devices:
                for action in sorted(ACTIONS):
                    has = (u["subject"], d.id, action) in grants
                    out.append('<tr><td>' + _e(u["display_name"] or u["email"] or u["subject"]) +
                               '</td><td>' + _e(d.name) + '</td><td>' + _e(action) +
                               '</td><td><form method="post" action="/admin/grant">' +
                               '<input type="hidden" name="csrf" value="' + token + '">' +
                               '<input type="hidden" name="subject" value="' + _e(u["subject"]) + '">' +
                               '<input type="hidden" name="device_id" value="' + _e(d.id) + '">' +
                               '<input type="hidden" name="action" value="' + _e(action) + '">' +
                               '<input type="hidden" name="enabled" value="' + ('0' if has else '1') + '">' +
                               '<button>' + ("Revogar" if has else "Conceder") + '</button></form></td></tr>')
        out.append('</table></section>')
        return _page("Admin • Gateway Lite", "".join(out))

    async def update_device(request: Request):
        try:
            form = await post_form(request)
            store.save_device(Device(
                id=form["id"], name=form["name"], host=form["host"],
                port=int(form["port"]), ssh_user=form["ssh_user"],
                key_name=form["key_name"], enabled=form.get("enabled") == "on"))
            return redirect_admin()
        except (ValueError, KeyError, PermissionError) as err:
            return PlainTextResponse(str(err), status_code=403)

    async def update_grant(request: Request):
        try:
            form = await post_form(request)
            store.set_grant(form["subject"], form["device_id"], form["action"],
                            form.get("enabled") == "1")
            return redirect_admin()
        except (ValueError, KeyError, PermissionError, __import__("sqlite3").IntegrityError) as err:
            return PlainTextResponse(str(err), status_code=403)

    async def check(request: Request):
        try:
            assert_admin(request)
            device = store.get_device(request.query_params["device_id"])
            result = execute(device, "hostname", timeout=10)
            state = "ONLINE: " + result.stdout.strip() if result.exit_code == 0 else "OFFLINE/SSH error"
            return _page("Teste SSH", '<h1>' + _e(device.name) + '</h1><p>' +
                         _e(state) + '</p><a href="/admin">Voltar</a>')
        except (PermissionError, KeyError, ValueError, OSError, __import__("subprocess").TimeoutExpired) as err:
            return _page("Teste SSH", '<p class="danger">Conexão indisponível: ' +
                         _e(type(err).__name__) + '</p><a href="/admin">Voltar</a>')

    app = Starlette(routes=[
        Route("/", landing),
        Route("/admin", admin),
        Route("/admin/device", update_device, methods=["POST"]),
        Route("/admin/grant", update_grant, methods=["POST"]),
        Route("/admin/check", check),
        Route("/auth/login", login),
        Route("/auth/callback", callback),
        Route("/auth/logout", logout, methods=["POST"]),
    ])
    app.add_middleware(SessionMiddleware, secret_key=session_secret, session_cookie="lite_admin_session",
                       https_only=True, same_site="lax", max_age=28800)
    return app
