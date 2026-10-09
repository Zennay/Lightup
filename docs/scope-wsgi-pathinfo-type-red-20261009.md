# LightUp scope boundary: WSGI `PATH_INFO` canonical type (RED acceptance)

**Status:** isolated offline RED contract, **not a security fix or target authorization proof**. Main baseline: `dd4072cdd1a2bc44a752ccbb7b1d0b6d56559da1`. Owner of the production `LightUpWebApp.__call__` route boundary: [PR #182](https://github.com/Zennay/Lightup/pull/182). This branch changes only a new test file and this new documentation file. It must not take over that owner’s `src/lightup/webapp/app.py`, [#202](https://github.com/Zennay/Lightup/pull/202) WebSecurity, [#1156](https://github.com/Zennay/Lightup/pull/1156) path-header overrides, [#1157](https://github.com/Zennay/Lightup/pull/1157) HTTP method case sensitivity or [#1162](https://github.com/Zennay/Lightup/pull/1162) form parser.

## Why this matters

`PATH_INFO` is WSGI-server supplied route identity, not an authorization credential. The application currently obtains it with `environ.get("PATH_INFO", "/") or "/"`, parses form and cookie, and passes any nonempty object to regular-expression route matching. An invalid nonstring value may raise an uncaught `TypeError` after doing body/session work; a `str` subclass can pass the regex and reach a privileged operator handler. These are **in-process WSGI fixture hazards** rather than proven remotely triggerable Nginx/Gunicorn exploitation. They should be denied consistently at the request boundary.

An app-owner implementation should admit only a canonical trusted built-in `str` path from the WSGI server (or explicitly document/justify a narrower safe type contract), reject invalid path metadata **before form reads and session lookup**, and preserve normal exact-string routing and tenant/CSRF requirements. Missing/empty `PATH_INFO` policy is out of scope and intentionally not asserted by this suite.

## Acceptance and evidence

Run on the immutable PR head:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_wsgi_pathinfo_type_red_20261009.py' -v
```

The real `create_app`, temporary SQLite `DomainStore`, and development + simulated production HTTPS/trusted-loopback WSGI settings exercise:

- Four `expectedFailure` **RED** canaries: bytes, integer, list, and `str` subclass `PATH_INFO` cannot become a request route, authorize an operator write or force body/session access.
- Four normal controls: an exact built-in string path with genuine operator cookie + body CSRF can create a client; client cookie with forged proxy identity cannot; unknown valid path cannot write; bad body CSRF cannot write or revoke the operator.
- No real targets, network/sockets, grants, scanners, proxy reload, workflow dispatch or production deployment initiated by the suite. Production is only a WSGI environment fixture.

**Critical interpretation:** `expectedFailure` counts as test-suite success while exposing an unresolved app-level gap. A hosted or VPS green job is **NOT proof** that the RED canaries are fixed. The source owner must change the actual app boundary, remove the four `expectedFailure` decorators, show four plain passing negative assertions and positive controls on the exact integration SHA, and obtain independent review. Installed ingress acceptance is separate: externally supplied HTTP cannot normally choose arbitrary Python `environ` object types.

## Promotion fence

Keep this branch **DRAFT/HOLD**; do not merge or activate real-target execution based on test-only work. Require exact-final-head hosted preflight, canonical permanent VPS `[self-hosted, zcloud, vps]` CI, app-owner integration, reviewer signoff, documented consent, target/capability/tenant/risk binding and immediate revocation enforcement before any live activation. A queued VPS check is **not** a pass. The project remains lab/plan-only.
