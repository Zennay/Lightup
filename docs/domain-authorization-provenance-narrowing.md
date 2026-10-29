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

## #177 — approved request is now a durable grant prerequisite

A new `grant_request_binding` source module provides conservative canonical
host/IP/CIDR comparisons. The domain grant constructor now selects and persists
**exactly one** approved request belonging to the engagement tenant. A caller
may provide `approved_request_id` explicitly. To retain the existing
operator grant form without modifying currently owned webapp source, omission
is allowed only when **one unique** approved request is a compatible match;
zero or multiple matches cause a fail-closed error. The persisted request must
have been genuinely submitted by a current same-tenant client user, separately
decided by a current operator, in `authorized_assessment` mode, before grant
creation, with a risk ceiling at least the grant risk. It must cover **all**
granted assets without implied DNS/IP aliasing, wildcard semantics, CIDR
rounding or public-target network inference.

The grant database schema now has nullable `approved_request_id` with a
foreign key to the original request. `DomainStore.__init__` adds the column
to existing SQLite files if missing; it **never fabricates a binding for
legacy grants**. A new grant write is atomic, including actual issuer role,
engagement owner/status, request provenance and approved scope constraints.
`list_authorization_grants` now **revalidates** the stored tenant relationship,
current approved request status/identity, decision chronology and scope/risk
at each read, filtering malformed, revoked-as-rejected, incomplete, legacy or
unbound rows. `get_current_grant` inherits this narrowing.

**Potential behavior change:** pre-existing unbound grants cannot be treated
as current, and operators must first have a genuine client-origin approved
assessment request. Ambiguous multiple approved requests require the new
explicit `approved_request_id` argument via a future operator UI
composition; the original web UI does not yet expose that selection. This is
intentional fail-closed behavior and is not production-ready without UI
composition and review. The review-only Readiness Desk remains available
separately for operational inspection of legacy unbound rows.

In addition, issuing and reading grants now fail closed for a **closed
engagement** or **inactive client**. Reading the current grant requires an
exact timezone-aware datetime rather than accepting falsy or naive arguments
as an implicit current instant. Neither operation edits a stored grant,
reactivates an engagement, or substitutes for the separate revocation
kill-switch owned by #100.

The binding is **administrative provenance**, not a separate signed proof of
client consent, authorization to scan real assets, live revocation verification
or release permission. Existing target-capable execution adapters and separate
durable resolvers still require independent binding/revocation composition.
**No real-target activation is enabled.**

## Boundaries and integration

- Source touched: `src/lightup/domain.py`, new `src/lightup/grant_request_binding.py`, and this documentation. No `webapp/app.py`, opt-in guarded portal, `engagements.py`, tests, QA suite, GitHub Actions, runners, deploy definitions, active scanning, evidence, or grant issuance code changed.
- Existing valid same-tenant grant rows remain readable; invalid tenant-duplicated rows are filtered.
- Existing approved/rejected requests are not automatically altered, revoked or repaired. A historical bad approval needs a separate owner-led data disposition.
- #177 source issuance/read binding is implemented on this branch, but it has **not** been composed into every independent execution-time authorization resolver or integrated into the actively owned web UI; real-target execution must remain disabled.
- The older #182 input-hardening PR and #1566 opt-in guarded portal must be composed by their owners: this source guard is defense in depth, not a substitute for proper web admission.
- No release/merge until normal branch CI, independent security/privacy review, actual client/operator consent+revocation gates and explicit human GO. Keep draft/HOLD.

## Direct artifact verification only

Inspect the installed `lightup.domain` module and package build on the registered VPS if authorized. No new QA, regression or test harnesses are requested or included. Verify resulting source tree and package without executing scans, grant issuance or target interactions.
