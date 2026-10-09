# Canonical WSGI PATH_INFO guard — owner integration and acceptance

**Current state: isolated functional producer, no production wiring.** `src/lightup/webapp/pathinfo_guard.py` is deliberately an independently testable, stdlib-only module. The current `create_app` does **not** instantiate this middleware. This PR must remain **DRAFT/HOLD** and is not a claim that LightUp currently enforces the guard. The production `src/lightup/webapp/app.py` file is owned by [PR #182](https://github.com/Zennay/Lightup/pull/182), and no other-worker path is changed here.

## The specific gap

Current `LightUpWebApp.__call__` dispatches WSGI `PATH_INFO` after form/session processing. The Python regular expression `^/clients$` can match `/clients\n` because `$` admits a final LF; its route matching also accepts a `str` subclass. A malformed nonstring path can cause a Python exception instead of fail-closed denial. These are concrete **in-process WSGI-contract problems**. The installed Nginx/Gunicorn exposure of a route containing LF, or exotic Python object `PATH_INFO`, has **not** been established. This PR neither changes proxy configuration nor interacts with real targets.

## Implementation

`canonical_path_info(environ)` inspects the canonical WSGI key without string coercion, percent-decoding, path unescaping, or normalization. It admits only a built-in `str` that is empty (app-root semantics), or begins with literal `/`, has at most 4096 characters, and has no ASCII control characters or DEL. The empty path maps to `/` in the validation return but **the wrapper does not rewrite the environment**; legacy `LightUpWebApp` already routes empty path as root. A missing key or noncanonical type fails closed.

`CanonicalPathInfoGuard(app)` checks this metadata **before entering the wrapped WSGI application**, so rejected paths cannot reach body reading, session lookup, route dispatch, operator writes or portal reads. It returns bounded generic `400 Bad Request` and security/no-store response headers. When explicitly configured with `production=True` (a strict built-in boolean, never a truthy coerced label), early denials also include the production `Strict-Transport-Security: max-age=31536000` header; development denials never advertise HSTS.

The guard is not an access token, scope grant, tenant check, risk policy, target authorization or an installed-ingress defense by itself. It must never be used to bypass owner-owned `WebSecurity`, request-form validation, session CSRF checks or source capability gates.

## Offline acceptance

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_pathinfo_guard_integration_20261009.py' -v
```

All methods use temporary SQLite and real `create_app` in development or simulated HTTPS/trusted-loopback production, without sockets, DNS, scans, grants, active assessments or deployment. Acceptance proves:

- Type/canonicality checks reject bytes, numeric/list/None/string subclass, relative paths, CR/LF/NUL/TAB/DEL and oversized inputs. The exact 4096-character limit, Unicode, and literal percent-encoded values are preserved without decoding.
- `/clients\n` is recognized as regex-dangerous even though the guard denies it.
- Denied paths do not call wrapped handlers, read request bodies, consult sessions, mutate the client database or disclose operator dashboard content. Production rejects retain HSTS, while development rejects omit it; non-boolean production flags are not allowed.
- Exact valid operator GET/POST remains functional; client impersonation hints and invalid CSRF remain denied independently of the route guard.
- A trailing-LF variant of `/logout` does not revoke a real operator session; a trailing-LF variant of `/portal/<client_id>/requests` does not add a tenant assessment request, in either WSGI environment. Both denial paths preserve session integrity.

## Production ownership and integration handoff

For app owner [#182](https://github.com/Zennay/Lightup/pull/182), suggested minimal integration (owner decides whether to wrap `create_app` or directly call the pure helper at the earliest line of `__call__`):

```python
from lightup.webapp.pathinfo_guard import CanonicalPathInfoGuard
app = CanonicalPathInfoGuard(create_app(store, security=security), production=security.production)
```

A guard only inside a late route handler is insufficient: invocation must happen before form/session work. If integrating via a direct call rather than middleware, preserve the same 4xx response headers and avoid accidentally catching failures as a 500. Existing application composition (e.g. finding export wrappers) needs separate owner review so **every actual entrypoint** is covered. This example is illustrative, **not a deployment change**.

Once owner integration lands, revisit [#1165](https://github.com/Zennay/Lightup/pull/1165) and [issue #1166](https://github.com/Zennay/Lightup/issues/1166): the five RED `expectedFailure` checks must become ordinary passing assertions on the **actual integrated app**, otherwise standalone middleware success is insufficient.

## Promotion stop line

Retain draft / no merge until exact-final-head hosted Python 3.11/3.14 and permanent self-hosted `[self-hosted, zcloud, vps]` CI success, app/security owner review, and composition with all production entrypoints. Installed reverse-proxy wire/path canonicalization is independent [issue #1158](https://github.com/Zennay/Lightup/issues/1158). Never enable real-target testing absent explicit customer consent, named asset/capability/risk and per-dispatch revocation checks. This work remains entirely offline, plan/lab-only.
