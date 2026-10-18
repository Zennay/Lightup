# Domain authorization provenance and tenant read narrowing

**Phase: INCUBATE · PLAN/LAB ONLY · DRAFT/HOLD.** This change narrows the existing LightUp domain API and does not activate real-target execution, authorize scans, grant consent, bypass release review, or alter CI.

## Product fixes

### #829 — tenant-consistent grant reads

`DomainStore.list_authorization_grants(ctx, engagement_id)` now selects persisted grant rows **through their owning engagement** and returns only records where the duplicated `authorization_grants.client_id` matches `engagements.client_id` and the engagement previously authorized by the caller. A corrupted cross-tenant grant is **never materialized as an AuthorizationGrant**. Existing `get_current_grant` calls inherit this directly and cannot choose that corrupt row as current. This is **read-only**: records are not repaired, deleted, reparented or silently granted authority to another tenant.

This is a **narrow production-source fix**, not another acceptance-only or simulated defect report. The previous #829 issue text was written for a dedicated acceptance-only worker while domain.py had several concurrent PRs. This branch deliberately keeps its source diff small and requires human composition review against outstanding domain PRs before merge.

### #673 — real client-origin assessment requests

`DomainStore.submit_assessment_request` no longer trusts a fabricated client `AccessContext` alone. It requires an **exact** real CLIENT_ADMIN or CLIENT_MEMBER role and checks the caller's **persisted** user ID, role and exact client ID, and the owning client's active status, while holding the same SQLite `BEGIN IMMEDIATE` write transaction that records the request.

This directly stops the default portal's synthetic operator-as-client view from being used as request provenance: the synthetic context carries an operator's user ID, so the source-level persisted role/tenant check denies the POST before any request row is inserted. Actual same-tenant client users retain the standard request submission path.

`DomainStore.review_assessment_request` now similarly verifies the actual **persisted operator identity** and validates that the request was made by a **different**, currently persisted client member/admin of the very same tenant. The approval/rejection update occurs under one write transaction with the recheck; type-confused/nonboolean decisions are denied. A fabricated operator context or a request created through the old synthetic operator path cannot be approved by the domain method. Administrative review still does **not** issue a scope grant.

## Boundaries and integration

- Source touched: only `src/lightup/domain.py`. No `webapp/app.py`, opt-in guarded portal, `engagements.py`, tests, QA suite, GitHub Actions, runners, deploy definitions, active scanning, evidence, or grant issuance code changed.
- Existing valid same-tenant grant rows remain readable; invalid tenant-duplicated rows are filtered.
- Existing approved/rejected requests are not automatically altered, revoked or repaired. A historical bad approval needs a separate owner-led data disposition.
- This does **not** fix #177: `record_authorization_grant` still requires true approved request→grant binding and canonical asset/risk revalidation before real-target execution can be permitted.
- The older #182 input-hardening PR and #1566 opt-in guarded portal must be composed by their owners: this source guard is defense in depth, not a substitute for proper web admission.
- No release/merge until normal branch CI, independent security/privacy review, actual client/operator consent+revocation gates and explicit human GO. Keep draft/HOLD.

## Direct artifact verification only

Inspect the installed `lightup.domain` module and package build on the registered VPS if authorized. No new QA, regression or test harnesses are requested or included. Verify resulting source tree and package without executing scans, grant issuance or target interactions.
