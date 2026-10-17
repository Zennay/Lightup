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
  and operator controls; foreign engagement rejection; expiry; and a durable
  database immutability check that remains green before *and* after a fix.
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

## Source-owner local repair oracle

A **throwaway** VPS checkout was temporarily edited to add the extra
`client_id=?` condition to the read query; five out of six source RED methods
then passed as ordinary tests, and the sixth did too. The initial strict
invocation of all 11 tests was 10 PASS, one failure in the *old positive
witness* test: it had asserted that the unsafe behavior must remain present.
That fixture has now been corrected to assert **only immutable durable state**,
which should hold both before and after a fix. Re-run the full strict suite on
the latest exact branch commit before considering the proposed source-owner
change ready. No production source was committed.

## W2 — strict bilateral source + authenticated WSGI composition (17 October 2026)

The same isolated owner branch now adds two new test modules and expands its
original SQLite acceptance to **18 genuine temporary-SQLite methods**.
The actual *unmodified* source has **6 ordinary PASS and 12 source-owned
expected REDs**. Newly pinned cases include bidirectional A/B corruption,
newer corrupt grant masking a valid older grant, BLOB tenant IDs, whitespace
aliases, SQL-shaped opaque values, and multiple corrupt rows.

**Real authenticated downstream UI proof:** a separate 5-method in-process
WSGI test creates an actual operator account and session in disposable SQLite
(no bound HTTP server). Original source gives 3 ordinary PASS and **2
expected source REDs**: `/clients/<fictional-A-id>` can show an
`Authorization current` badge and a grant reference copied from a
pre-existing corrupt B-owned stored row. This is an operator **display and
read-integrity flaw**, *not* evidence of an unauthorized remote scan,
cross-tenant session bypass, or execution grant.

**Independent source mutation matrix:** new
`tests/test_scope_829_owner_repair_oracle_20261017.py` makes ephemeral
copies of the original package and runs **all 23 REAL (18 SQLite + 5 WSGI)
methods without any expectedFailure wrappers**, inside isolated subprocesses.
Five normal oracle methods pass when:
- the original owner source gives exactly **14 strict REDs**;
- the full tenant-owner SQL equality fix yields **23/23 ordinary PASS**;
- three weaker alternatives are strictly rejected: trimming opaque tenant
  IDs, limiting the SELECT to one row, or filtering only
  `get_current_grant` while keeping `list_authorization_grants` leaky.

At exact branch HEAD for the W2 mutation matrix, combined source suite is
**28 methods = 14 ordinary PASS and 14 deliberately open source
expectedFailures** on connected authorized zSSH (Python 3.14.4).
The two changed modules and WSGI tests are exclusively NEW owner files.
No source owner or shared workflow is modified. Python emits unrelated
historical SQLite ResourceWarnings in original upstream paths; none of these
are counted as a passing release gate.

**Important:** `expectedFailure` is explicitly never green production
security. When the source owner integrates the fix, all 14 source RED tests
must be made ordinary assertions and the full 23-case package must pass on
the actual production source, with exact approved SHA CI and independent
human security/privacy sign-off. The synthetic oracle itself does not
repair production or authorize any activity.
