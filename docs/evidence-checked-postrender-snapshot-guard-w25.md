# W25 — optional canonical post-render session snapshot guard

Status: **DRAFT / LAB ONLY / NOT WIRED**. Issue [#1197](https://github.com/Zennay/Lightup/issues/1197), on immutable W11 checked WSGI owner [#1198](https://github.com/Zennay/Lightup/pull/1198). Independent [expected-RED test #1202](https://github.com/Zennay/Lightup/pull/1202) remains separate.

## Scope

New `src/lightup/webapp/checked_postrender_session_contract.py` exposes `is_canonical_postrender_session(snapshot, expected_context)`, a pure, side-effect-free **optional helper**. It requires exact `AccessContext` values, an exact two-element tuple, an unchanged principal/role/tenant, and a nonempty exact string CSRF token. Malformed containers, tuple/string subclasses, arbitrary objects, changed identities and empty tokens are refused without coercion or introspecting hostile subclasses.

The helper does **not** read a session, authenticate a user, prove the source of a tuple, lock an account, install a route, or ensure the authorization state stays fixed during transmission. The owner must make the real server-side `DomainStore.session_context(token)` call and decide whether the canonical CSRF token checks match all supported session providers. The existing W11 handler is unchanged and **does not import the helper**. Therefore this is a reusable proposed remediation, not production enforcement, and must not be advertised as a live security fix.

## Safe adoption sequence

1. Owner of #1198 confirms contract against real `DomainStore.session_context` and current role/tenant semantics.
2. Source owner makes a separately reviewed call-site change using this helper after checked CSV rendering; all failures must return generic 403 **without any CSV response**. Keep pre-render authorization, route/session admission and post-render revalidation.
3. Exercise W24 real WSGI synthetic denial cases, original W11 WSGI acceptance, full regression, source/security/privacy review and exact-head **permanent self-hosted VPS CI**, followed by real installed ingress/browser acceptance before deployment approval.

Only new source/test/docs paths; no default portal/CLI, existing auth/domain/export, main, real clients, target interaction, scans, authorization grants, remediation/retest or deployment. **M3/M7 PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY.**
