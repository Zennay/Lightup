# LightUp #1284 — real WSGI error-detail privacy acceptance

**State:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY. All data is synthetic, local and disposable; no user/customer records, targets, grants, network, tools, remediation or retest.

## Reproducible source finding

Current `src/lightup/webapp/app.py` handles domain errors in `LightUpWebApp._dispatch`:

```python
except (KeyError, ValueError) as exc:
    body = f"<h1>Request failed</h1><p class=\"sub\">{_e(exc)}</p>"
    return Response(_page("Error", "", body, auth), status="400 Bad Request")
```

Even though HTML is escaped (XSS protection), the raw error *content* is still returned. This can expose opaque identifiers or future authorization/private domain context. The direct, offline reproducible route is a valid operator WSGI session requesting `GET /clients/PrivateResourceMarker1284`; the current domain `get_client()` raises `KeyError("unknown client ...")`. No evidence exists of any real production secret exposure.

## Independent integration acceptance

Add-only `tests/test_wsgi_error_privacy_1284.py` runs nine genuine in-process WSGI methods against a *temporary on-disk SQLite database*, creating a real operator, client, operator session and client session. It tests:
- normal operator `GET /clients`;
- non-cached, unframeable standard 400 security headers;
- anonymous redirect and client principal isolation *before* private handler;
- client-role and CSRF mutation denials, comparing durable client counts;
- legitimate invalid form preserves database state;
- **two intentionally unresolved expected RED**: unknown-resource ID and domain validation detail must be absent from 400 response body.

`OK (expected failures=2)` is **not** a production fix: default 400 currently echoes exception messages. Do not remove `@expectedFailure` or call these PASS until the webapp/source owner implements a sanitized error response, these two tests are converted to ordinary passing tests, and independently revalidated.

## Non-conflicting ownership

Only new tests and this contract document. **No edits** to existing `src/lightup/webapp/app.py`, `forms.py`, `security.py`, DomainStore, other workers' scope branches/PRs, any default source, configuration, production ingress, deployment, or targets. This is separate from #1275 persisted risk-decision write lineage and #1166 path admission.

## Required production-owner behavior

Return a generic non-echoing browser-safe 400 body with no raw exception details, resource identifiers, secrets, tracebacks or internal database fields. Keep the 400 HTTP status, no-store/security headers and correct response content encoding/length; preserve server-side diagnostics only in a separate controlled redacted sink. Ensure no visibility difference can bypass tenant/operator and CSRF checks. Independently review relevant exception families before broadening the catch; do not silently swallow authorization violations.

## Release gates

Latest-main compatibility, exact branch HEAD GitHub-hosted Python 3.11 and 3.14 unit + real producer integrations, separate **permanently registered** `[self-hosted, zcloud, vps]` VPS CI, original web source-owner approval, independent privacy/security review and explicit human release approval. Hosted green and expected-RED are insufficient. No deploy or live ingress action in this task.
