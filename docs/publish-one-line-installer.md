# Publishing the AI Lab Linux one-line installer

**2026-10-17: the Caddy publication requires one independent human-admin action. Until that happens, the HTTPS endpoint still returns 404.**

## Pinned artifacts

- Public URL: https://gateway.debasti.com/install.sh
- Bootstrap commit: 13a06d291b3e9c2b17025c1c54cd657fc68e39f2
- Bootstrap SHA-256: 367fb8d46b0efcac3c319c92174af29e96e943ae18cdbeb7a8e62576c0857127
- Publisher commit: 7455f5aeadc725c6fa0fc35e697d4f5a9c780be9
- Publisher SHA-256: ded664d225c13a13819186a02427ca2618c85032e2b9adf026c6e1fd813a7f5d
- Publisher source: [scripts/publish_linux_bootstrap.py](../scripts/publish_linux_bootstrap.py)

The publisher verifies the pinned immutable bootstrap and refuses conflicting Caddy configurations, symlinks, unauthorized ownership and changed content. It validates candidate Caddy syntax before touching live services, backs up the original root-owned Caddy configuration, installs a root-owned static file, reloads Caddy and verifies the public response. If publication fails, it attempts automatic config restoration and reload. It NEVER modifies the underlying pairing, approval, MCP or target-executor service and NEVER grants generic sudo.

## One-time publication — original Oracle administrator only

On the primary Oracle, open an **independent human** terminal as ubuntu@ai-lab-gateway-01 (NOT MCP user ai-maintenance). Download to a private home directory, verify the source SHA-256 and perform the read-only --check:

~~~sh
set -e
D="$(mktemp -d "$HOME/ai-lab-publish.XXXXXXXX")"
chmod 700 "$D"
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  'https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/7455f5aeadc725c6fa0fc35e697d4f5a9c780be9/scripts/publish_linux_bootstrap.py' \
  -o "$D/publish.py"
printf '%s  %s\n' \
  'ded664d225c13a13819186a02427ca2618c85032e2b9adf026c6e1fd813a7f5d' \
  "$D/publish.py" | sha256sum -c -
/usr/bin/python3 -I "$D/publish.py" --check
~~~

Expected: AI_LAB_BOOTSTRAP_PUBLISH_CHECK_OK, route_state: ready_to_add, and the known expected hash. On any failure, stop.

The original human administrator then runs:

~~~sh
sudo /usr/bin/python3 -I "$D/publish.py" --apply
~~~

Expected: AI_LAB_BOOTSTRAP_PUBLISHED and the same pinned SHA-256. This local sudo is distinct from agent/MCP supervision; it is not delegated to ChatGPT.

**Verification:** independent HTTPS GET of https://gateway.debasti.com/install.sh returns 200 and bytes with the expected bootstrap SHA-256; check that existing MCP and pairing endpoints still respond. Preserve the administrative console throughout the test. Root backup path is /var/backups/ai-lab-bootstrap-publish-v1/Caddyfile.before-install-sh.

## The simple command for the new disposable Ubuntu

Only **after** verifying the endpoint publicly, execute as a normal Ubuntu user (never via sudo):

~~~sh
curl -fsSL https://gateway.debasti.com/install.sh | sh
~~~

The installer checks pinned sub-artifact SHA-256, prepares the non-root ai-gateway account using the original Linux human's sudo permission, and displays the device code. The human enters the exact code privately in authenticated ChatGPT; the agent looks up the device and asks for explicit identity confirmation. Device approval **never authorizes root**.

**Security caveat:** curl-to-sh places trust in HTTPS and in the static bootstrap served by this host. If the host were compromised, embedded sub-artifact checks would not by themselves protect the first script. A verify-then-run alternative and separate signed releases remain recommended for higher assurance.

**Not yet complete:** live clean-device ChatGPT approval, signed SSH activation through real Gateway, reboot persistence, release readiness, and optional independently supervised root. Do not test on the two existing Oracle servers, Raspberry or WSL.
