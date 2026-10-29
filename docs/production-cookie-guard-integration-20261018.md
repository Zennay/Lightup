# LightUp production Cookie admission integration · 18 October 2026

**DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY. No merge or deploy.**

## Actual production entrypoint change
The existing `create_production_app()` Gunicorn factory now composes the original exact opt-in `CookieEnvelopeGuard` from owner [#1169](https://github.com/Zennay/Lightup/pull/1169) around the real `LightUpWebApp` after the original strict production environment, HTTPS origin and loopback proxy requirements are constructed.

An incoming Cookie header with ambiguous/duplicate session credential identity, malformed representation or invalid canonical token shape receives a generic 400 before request body consumption, application authentication, session lookup, CSRF, mutations or handler admission. This does **not** authenticate a user: unchanged authoritative SQLite session state still decides. Existing successful sessions/routes are passed through unchanged. The wrapper applies to *normal production creation*, not only a demonstration or alternate opt-in factory.

## Source ownership and release limitations
- Exact unmodified base: [#1169](https://github.com/Zennay/Lightup/pull/1169) SHA `31055e7f5de9046405afea14bc945feb8f21d8be`. The existing guard source, its original acceptance and worker branch are not modified; only `src/lightup/webapp/production.py` plus this independent integration note differ from base.
- Dev `create_app()` is deliberately unchanged. This specifically narrows production ingress and does not claim all development WSGI use is protected.
- WSGI cannot observe if Nginx/Gunicorn collapsed duplicate *wire* Cookie fields; installed reverse-proxy semantics and compatibility with third-party cookies must be reviewed by the original security/ingress owner. Browser session origin remains under existing session and CSRF controls.
- Mandatory original exact-head hosted and permanently registered named VPS CI, privacy/security source-owner review, genuine separate client/operator consent and at-use revocation for active assessments, and explicit HUMAN GO remain release gates. No QA/test suites added, modified or manually run; no grant, scan, target interaction, network deployment or auth bypass.
