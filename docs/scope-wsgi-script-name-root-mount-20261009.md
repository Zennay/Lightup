# WSGI SCRIPT_NAME root-mount admission (isolated, opt-in)

## Scope of this slice

LightUp's current web shell expects to be served at the root path. A WSGI
`SCRIPT_NAME` represents the application mounting prefix, while `PATH_INFO`
represents the path passed to the application. Conflicting mount metadata can
produce two interpretations of the public URL. The existing app dispatches
only on `PATH_INFO`; it does not independently validate a root-only mount.

This change adds `RootMountGuard` in
`src/lightup/webapp/root_mount_guard.py`, a reusable pre-auth wrapper. It
accepts only **missing** `SCRIPT_NAME` or **exact built-in** empty-string
`SCRIPT_NAME`. Nonempty, polymorphic and malformed representations receive a
generic 400 before the wrapped web app can parse forms, look up a session,
write a tenant/client, authenticate a login or revoke a session.

An isolated **opt-in production factory**,
`create_root_mount_guarded_production_app()`, constructs the existing
`create_production_app()` result and wraps it with the exact production mode.
It is not registered as the deployed Gunicorn entrypoint. The factory continues
to require the existing HTTPS origin and absolute database configuration.

The rejection response contains no cookies, forbids caching/framing, and
preserves HSTS when configured with `production=True`. The mode is **required**,\nmust be an actual `bool`, and must match the wrapped LightUp app's\n`WebSecurity.production` setting; accidental omission or mismatch fails at\nconstruction rather than weakening production denial headers. `SCRIPT_NAME` is never an authorization grant; accepted
requests still require their original session, role, tenant and CSRF checks.

## Offline evidence

`tests/test_scope_wsgi_script_name_root_mount_20261009.py` exercises the
actual WSGI application and a temporary SQLite `DomainStore`, in both
development and simulated HTTPS/loopback-proxy production configuration:

1. Nonroot/malformed/case-polymorphic mount metadata cannot call the
   session resolver or read even an unreadable request body.
2. An operator's legitimate session and existing tenant records survive
   rejected client writes and rejected logout/login requests unchanged.
3. A canonical empty/missing mount preserves protected reads and existing
   CSRF checks, and allows an explicitly authorized operator write.\n   Client-admin sessions remain barred from operator and other-tenant routes\n   despite spoofed prefix hints.
4. `X-Script-Name`, `X-Forwarded-Prefix` and other client-supplied hints
   cannot substitute for the actual WSGI mount value.
5. The HSTS policy is present on early-denied simulated production responses.\n6. Explicit production configuration is mandatory and cannot conflict with\n   the wrapped application's configured security mode.

Run with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_wsgi_script_name_root_mount_20261009.py' -v`; the hosted
`lightup-preflight.yml` and self-hosted `lightup-ci.yml` workflows also
discover the new test file.

## Integration and evidence gates — **NOT MET by this PR**

- This is an **optional wrapper and optional production factory, not a deployed entrypoint switch**.
  The source owner must compose it with the independently owned
  `PATH_INFO`, method, cookie, form and proxy guards. Do not edit their files
  or assume all wrappers are active because one passes its own tests.
- An empty `SCRIPT_NAME` contract assumes a **root-mounted** LightUp.
  Any planned subpath deployment needs a separately reviewed, explicit
  configuration and corresponding generated URLs; do not silently widen this
  allowlist.
- Synthetic WSGI dictionaries cannot prove installed Nginx/Gunicorn behavior
  or how malformed wire requests are normalized before the WSGI boundary.
  Require isolated installed-ingress acceptance for `SCRIPT_NAME` +
  `PATH_INFO` combinations and exact protected-route mapping.
- Keep DRAFT/HOLD until the integrated **exact-final-SHA** hosted checks,
  canonical permanent VPS CI, independent security/source-owner review,
  installed-ingress proof and deployment decision are all green.
- Nothing in this PR enables active assessments, grants, scanners, target
  interaction, proxy reloads, production deployment or an attack path.
