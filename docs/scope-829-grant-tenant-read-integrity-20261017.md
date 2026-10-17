# Scope #829 — tenant-lineage revalidation on durable grant reads

**Project:** LightUp · `INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD`.  
**Owner isolation:** entirely NEW issue-specific acceptance files; **no** modifications to
`src/lightup/domain.py`, active source owners, CI workflow, runner, web, scans,
grant-execution code or real customer data.

## Source-confirmed problem

The existing `DomainStore.list_authorization_grants(ctx, engagement_id)`
authenticates the requested engagement's tenant, but then selects durable grant
rows on **engagement_id alone**. The persisted `authorization_grants.client_id`
can therefore be inconsistent with `engagements.client_id` after a legacy or
corrupt data write. `_grant_from_row` copies that inconsistent value into an
`AuthorizationGrant` without lineage verification; `get_current_grant` consumes
the same list and may surface that grant as current.

A correct grant-read implementation MUST compare *persisted row.client_id*
to the actual, authorized engagement owner, not merely check the requesting
user's client context. Operator reads are subject to the same row-level
coherence check. Never repair or delete corrupted database rows during reads.

## Reproduction and acceptance tests

`tests/test_scope_829_grant_tenant_read_integrity_20261017.py` uses a fresh
temporary SQLite database and entirely fictional tenants A and B. Each test
uses the real DomainStore constructor and public grant APIs.

- Five normal tests: canonical tenant A current grant; independent tenant B
  and operator controls; foreign engagement rejection; expiry; and a passing
  **source vulnerability witness** that proves the mismatched grant appears in
  both the list and current-grant response, without mutating the database.
- Six explicitly **expected source failures**: client read, operator read,
  client current-grant, operator current-grant, mixed valid/corrupt rows,
  and a persisted unknown client ID.
- The artificial corruption is restricted to disposable local SQLite fixtures.
  No grant is issued for any real target/client and no authorization bypass is
  exercised against an installed service.

On the **unmodified original code**, the test runner must show **11 methods,
5 ordinary passes, 6 expected failures**. An `OK (expected failures=6)`
line means **the source defect is still open**. Those expected-failure
decorators must be dropped once the owning implementation is changed, so
future CI requires all 11 methods to pass ordinarily.

## Suggested implementation handoff — source owner only

In `DomainStore.list_authorization_grants`, after authenticated
`get_engagement(ctx, engagement_id)`, filter grant rows with both:
`WHERE engagement_id=? AND client_id=?`, binding the authorized
`engagement.engagement_id` **and** `engagement.client_id`. Preserve
newest-first ordering. Ensure `get_current_grant` inherits the same
fail-closed filter and that read-only calls never normalize corrupt rows.
An equivalent validated join to engagements is acceptable. The source owner
must review composition with other authorization/data-integrity branches.

## Release boundaries

This acceptance suite is **not** itself a repair. No merge, production deploy,
real scans, real targets, grant authority, handler dispatch or security sign-off
follows from this evidence. Genuine client + operator consent, per-use
revocation, security/privacy review, approved-release exact-head CI on the
permanent named VPS runner and explicit human GO remain mandatory.
Avoid redundant canonical workflow dispatch while issue #1144 is unresolved.
