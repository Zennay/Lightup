# Scope #1284 — explicit opaque WSGI 400 response adapter

**Opt-in only / not deployed.** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY.

## Why

Existing `LightUpWebApp._dispatch` interpolates escaped domain `KeyError`/`ValueError` into HTTP 400 response HTML. This may reveal resource identifiers or authorization/private error text. HTML escaping does **not** provide data confidentiality. [Issue #1284](https://github.com/Zennay/Lightup/issues/1284) and separate tests-only parent cover expected RED on the legacy default.

## Actual opt-in source

`src/lightup/webapp/opaque_error_wsgi_optin.py` adds `OpaqueErrorWSGI`, explicitly constructed as:

```python
from lightup.webapp import create_app
from lightup.webapp.opaque_error_wsgi_optin import OpaqueErrorWSGI

# For synthetic lab proof only; this DOES NOT reconfigure deployed routes.
guarded_app = OpaqueErrorWSGI(create_app(disposable_store))
```

The wrapper accepts **only the exact current synchronous `LightUpWebApp` class** and never reinterprets route, user, session, host, origin, CSRF, grant, target or capability. It consumes/discards the original 400 body and returns a constant safe HTML body; original status, CSP, frame/no-cache protections and other headers remain. It corrects Content-Type/Length for the replacement, removes any stale ETag, never emits raw domain exception text, and passes all non-400 responses through unchanged. This is only a proof of the eager stdlib shell WSGI contract; arbitrary streaming WSGI apps and the `write()` interface are explicitly unsupported.

`tests/test_opaque_error_wsgi_optin_1284.py` uses 10 actual authenticated disposable SQLite WSGI tests, verifying nonleaking unknown-resource ID, nonleaking validation text, original default remaining unmodified, correct replacement length/type/security headers, positive valid authorized POST, unchanged operator normal GET, anonymous/client/CSRF refusal, no illegal DB mutation, and session continuity after error.

## Important limitations

- **The original `create_app()`, CLI and production ingress are unchanged and unguarded.** Only explicit import/use of the opt-in wrapper changes 400 responses.
- Existing exception text is still generated inside the original in-process app; this wrapper prevents it from reaching **outbound WSGI response bytes**, not in-process allocations, logs, arbitrary upstream middleware or future headers.
- Do not infer response privacy for non-400 failures, streaming WSGI apps, different factories, installed proxy/Gunicorn, client/browser or target behavior.
- Source owner must decide whether to integrate a simpler *native* sanitized catch in `webapp/app.py` after independent review. Never silently change original 400 semantics, privacy controls or authorization behavior.

## CI and release requirements

Source exact-head hosted Python 3.11/3.14 unit + real producer integration, separate permanently registered `[self-hosted, zcloud, vps]` CI, current-main composition, original web owner review, independent privacy/security and explicit human release authorization. The tests-only parent retains intentional expected RED for the default implementation. No production claim, deployment, customer input, scan, grant, external network/model or real remediation.
