# WSGI form envelope strictness — fail-closed admission

**Scope:** `src/lightup/webapp/forms.py`, a narrow parser used by privileged
web routes. This change affects only synthetic/malformed WSGI envelopes and
does not enable target execution or issue any authorization grants.

## Security invariant

The WSGI environment belongs to the web server, not to the client. Still,
a buggy/misconfigured reverse proxy or middleware may supply unexpected
values. Malformed framing and stream values **must not** become an unhandled
server exception or bypass authentication/CSRF due to polymorphic falsey
metadata.

Before looking up any authenticated session or invoking a mutation:

- Reject any nonempty or nonstring `HTTP_TRANSFER_ENCODING` value, including
  falsey `False`, `0`, `[]`, and `{}`. Missing or an exact empty string
  remains accepted as the normal no-transfer-hint state.
- Reject nonstring `CONTENT_TYPE` with 415. Normal URL-encoded MIME type
  remains accepted with optional parameters.
- Require the request stream, when declared `CONTENT_LENGTH > 0`, to yield
  **actual bytes** of exactly that length. Missing/unreadable/typed streams
  must raise `FormError` (400), never `KeyError`, `AttributeError`, or
  uncaught expected I/O faults.
- Preserve rejection of truncated streams, malformed percent escapes,
  duplicate sensitive keys and oversized/ambiguous declared lengths.
- Keep no mutation, no session lookup on parser denial, and no session
  revocation. On valid framing, existing operator role and CSRF checks
  remain mandatory.

## Regression coverage

Run on branch / immutable commit with the existing CI matrix:

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_wsgi_form_envelope_strictness_20261009.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

The new suite exercises both `read_form` directly and the **real WSGI
`LightUpWebApp` + temporary SQLite**. It asserts malformed input is
rejected before session lookup, that existing operator sessions survive, and
that forbidden input cannot create any client.

## Boundaries and release hold

This is **in-process parser hardening**, not proof that Nginx/Gunicorn
detect all request-smuggling variants or duplicate wire headers. Separate
[issue #1161](https://github.com/Zennay/Lightup/issues/1161) covers
installed-ingress synthetic CL/TE/desync acceptance; related isolated WSGI
framing tests are in [PR #1160](https://github.com/Zennay/Lightup/pull/1160).

No changes to `webapp/app.py` (owner #182), `security.py` (owner #202),
Nginx templates (owner #1155), ToolExecutor (owner #107), or other worker
branches. No network, DNS, scanner, actual targets, grants, deployment or
proxy reload.

**DRAFT/HOLD:** require immutable same-head hosted Python 3.11/3.14
preflight + real-producer integration, **canonical permanent VPS CI**, and
independent review before merge/release. Do not activate real-target tests.
