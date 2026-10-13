# LightUp #1284 · W4 — fixed-header 400 privacy seal (synthetic opt-in)

**Phase: INCUBATE M3/M7 / PLAN-LAB ONLY. DRAFT/HOLD · NO MERGE · NO DEPLOY.** This branch is a safe opt-in reference, not a replacement for installed ingress, and does not authorize an assessment or touch any target.

## Distinct privacy/integrity finding

The earlier opt-in `OpaqueErrorWSGI` in [DRAFT #1286](https://github.com/Zennay/Lightup/pull/1286) correctly removes unknown header **names** when replacing a 400, but the approved security header names could still carry potentially unsafe upstream **values**. For example, a synthetic source returning `Cache-Control: public`, `Content-Security-Policy: default-src *`, `Strict-Transport-Security: max-age=0`, `X-Frame-Options: ALLOWALL` would be forwarded by the original optional header allowlist. These are **theoretical synthetic regression vectors**, not observed real customers or active ingress exploits.

## Add-only independent W4 implementation

Pinned parent is immutable [DRAFT #1287](https://github.com/Zennay/Lightup/pull/1287) at `ca38114040c0387393bc1d5221e78f47f2964a84`. This PR adds **only three new paths**:

- `src/lightup/webapp/production_fixed_headers_optin.py`: explicit `create_fixed_header_opaque_production_app(environ=None)`. Delegates original production config/HTTPS proxy checks to opt-in W3 factory, then applies an exact-class, production-only final WSGI response seal. For HTTP **400 only**, discards upstream body, all copied headers and their values; emits only literal generic HTML and a **fixed canonical security-header policy** (CSP default-src none, no forms, no framing, no-store, no-referrer, nosniff, X-Frame-Options DENY, HSTS max-age 31536000, precise Content-Length/Type). No dynamic response metadata is reused. Every **non-400** response is passed through byte-identical, retaining authentication, redirects, cookies and CSRF.
- `tests/test_production_fixed_headers_optin_1284.py`: **14 synthetic real-WSGI, disposable on-disk SQLite test methods**, including injected hostile *allowed security header values*, duplicate/unknown headers, Cookie/Location propagation denial, authenticated unknown-ID and bad-form privacy, fixed deterministic responses, normal operator GET and valid POST equivalence, client/anonymous/CSRF/same-origin/proxy denial, secure login/logout and early reject-before-session/body-read.
- This review contract.

The original `src/lightup/webapp/app.py`, `security.py`, `production.py`, #1285/#1286/#1287 source/branches, all original source owners, default factories/CLI, production deployment, target execution and unrelated workers remain **untouched**.

## Narrow trust assumptions and limits

This is an **additional** opt-in WSGI seal atop the W3 optional factory, not activated by default and not an installed Nginx/Gunicorn test. A malicious/confused *in-process* custom or monkeypatched WSGI application is simulated only in-memory to prove header value filtering. The final wrapper supports only the original eager/synchronous LightUpWebApp / OpaqueErrorWSGI type composition, not streaming WSGI, writes, async servers, arbitrary middleware or post-transmission error handling. It does not stop the original source from creating a private string in memory; it prevents outbound 400 body/header disclosure at this specific wrapper. 401/403/404/413/5xx behavior remains unchanged, and no extra authority is granted. Parent two `@expectedFailure` default-source defects remain unresolved.

## Release gates

Keep DRAFT/HOLD/NO MERGE/NO DEPLOY until exact-final-head hosted Python 3.11 + 3.14 unit and producer integrations, genuine permanently registered `[self-hosted,zcloud,vps]` CI, independent privacy/security review, original web-source owner approval, latest-main composition and explicit human release authorization. Do not equate hosted green or expected RED with permanent runner proof or production security. No clients, scanning, external network/models, grants, remediation, retests, tools or deployment.
