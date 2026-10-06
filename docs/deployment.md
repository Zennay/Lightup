# Deploying the web application behind a local TLS proxy

The production factory requires explicit configuration; it never silently
falls back to development mode. The core `lightup serve` command remains a
loopback HTTP development server.

## Install and configure

Use a dedicated OS user `lightup`, a virtual environment at
`/opt/lightup/venv`, and the reviewed release checkout at
`/opt/lightup/current`. Install the optional web dependency:

```sh
/opt/lightup/venv/bin/pip install '/opt/lightup/current[web]'
```

Create `/etc/lightup/web.env` with the actual HTTPS origin and persistent DB:

```text
LIGHTUP_PUBLIC_ORIGIN=https://lightup.example.com
LIGHTUP_DB=/var/lib/lightup/web.db
LIGHTUP_TRUSTED_PROXY_IP=127.0.0.1
```

Replace the example hostname. The origin must have no path, credentials,
query or fragment. Missing/invalid origin or a relative DB path aborts startup.
The proxy must be local; remote proxy addresses are deliberately unsupported.

Use `deploy/lightup.service` as the systemd unit. Create the dedicated user and
directories with ownership matching that unit. Bootstrap an operator with the
existing `create-operator` CLI under that user, using the same database path.
Do not put passwords or model keys in the unit or source control. Back up an
existing database before replacing a release.

Install and configure Nginx separately, using `deploy/nginx.conf.example`.
Supply a valid certificate for the chosen hostname and validate with
`nginx -t` before reload. This repository does not provision DNS/certificates,
open firewall ports, or alter existing virtual hosts. The template serves HTTPS
only; an HTTP-to-HTTPS redirect, if desired, must use the fixed configured
hostname, never an arbitrary incoming Host.

## Enforced request boundary

- Gunicorn binds only to 127.0.0.1. The app requires the exact configured proxy
  socket peer and `X-Forwarded-Proto: https`; direct plaintext traffic fails.
- Development mode also rejects any present non-loopback socket peer before
  trusting a loopback-looking Host header. Missing peer metadata is accepted
  only for direct in-process WSGI use; forwarding headers cannot make a remote
  peer local.
- Host must match the configured origin, including the effective port.
  X-Forwarded-Host and X-Forwarded-For cannot override this check.
- Every production POST, including login, requires the same Origin, or a
  same-origin Referer when Origin is absent. An invalid Origin never falls
  back to Referer. Cross-site Fetch Metadata is rejected. Authenticated writes
  also retain the session CSRF check.
- Session creation and deletion use Secure, HttpOnly, SameSite=Strict cookies.
  Responses include HSTS (one year, without subdomains/preload) and no-store.
- The proxy overwrites forwarding headers; request buffering and 64 KiB body
  limits protect the upstream. Nginx header/body inactivity limits are 10s.
  Gunicorn uses two synchronous workers with a 30s worker timeout and 20s
  graceful shutdown. These settings concern the web app, not model workers.
- The local proxy and local OS users remain within the deployment trust
  boundary. Never expose the upstream listener or use wildcard proxy trust.

Application guards do not configure TLS themselves. A real HTTPS browser
acceptance test is still required on the selected hostname before public use.

## Verification and rollback

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python scripts/smoke_web_deployment.py
```

The smoke starts the actual Gunicorn factory on an ephemeral loopback port,
uses a temporary database, and checks proxy guards, sign-in, Secure-cookie
attributes, authenticated access and logout replay. It does not simulate a
certificate or claim to test the public Nginx/TLS deployment.

Before release, check HTTPS login and logout from a browser and confirm that
other client portals remain inaccessible. Keep the prior release and a
database backup; rollback switches the checkout/service back without deleting
state. These changes add no database migration.

Configuration references:
- https://docs.gunicorn.org/en/stable/settings.html
- https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- https://nginx.org/en/docs/http/ngx_http_core_module.html
