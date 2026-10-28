# LightUp WSGI domain error confidentiality · issue #1284

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No production merge, deployment or active assessments.

## Product change
The operator/client WSGI dispatcher still resolves identity, tenant access, CSRF and routes through the unchanged original source. When an authenticated handler reports a `KeyError` or `ValueError`, the browser now sees a fixed, actionable generic 400 explanation rather than HTML-escaped `str(exception)`.

Escaping untrusted exception bytes is not confidentiality: an unknown client ID or sensitive input could previously appear inside the authenticated error page. This source change does not rely on a separate opt-in adapter to protect the default web factory.

## Preserved behavior and limits
- Existing `TenantIsolationError` handling remains 403, with existing anonymous redirect, portal tenant checks, CSRF and operator-only controls unaffected.
- `Response` remains responsible for the original content length, anti-framing/CSP, `no-store`, referrer, and content-type headers; production HSTS is still appended by the original WSGI entry point.
- The exception is **not** logged with potentially sensitive identifiers by default. Operators can use server-side tracing under their own privacy policy; raw exception details must not be sent to the browser.
- This corrects the default generic error rendering only. It does not assert broader domain authorization readiness, fix unrelated state/consent issues, issue grants or add scan capability.
- Historical draft #1285 and opt-in adapter drafts #1286–#1288 remain untouched and require original owner integration decisions.

## Integration/release
The implementation changes the original production-source dispatcher; source-owner, privacy/security review and unchanged hosted + registered permanent named VPS exact-head CI, genuine distinct client/operator consent with at-action revocation, and explicit HUMAN GO remain mandatory. No new QA/regression/test suite is authored or run under the 17 October 2026 execution policy.

## Additional default portal read-only source narrowing · #673
- A signed-in operator retains authorized GET access to a client's portal but sees an explicit read-only request notice, **not** the client's submit-request form.
- The original POST `/portal/<client_id>/requests` handler now refuses the operator role and mismatched/nonexistent client session with a 403 **before** creating a synthetic portal `CLIENT_ADMIN` context, parsing submission risk/assets, or calling the database write.
- Real signed-in client sessions for their own tenant keep the existing form and submit flow. Existing dispatcher authentication/tenant/CSRF and operator review routes are unchanged; original independent [domain request-origin and grant lineage source #1570](https://github.com/Zennay/Lightup/pull/1570) is not modified and must be integrated separately.
- The portal UX and domain enforcement are defense in depth, not proof of independently authenticated owner consent or permission to issue assessment grants. Original web input owner [#182](https://github.com/Zennay/Lightup/pull/182) requires a deliberate source-composition review, not a silent takeover.
