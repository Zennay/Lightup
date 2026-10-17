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

The first local owner-fix oracle validated equality between the stored
`authorization_grants.client_id` and the previously fetched authorized
`engagement.client_id`. **That simple two-parameter SELECT does not fully
protect against an engagement owner changing between those two SQLite reads.**
W3 proved this second in-process read-order gap with two deterministic
temporary-SQLite regression cases.

A stronger single-statement, owner-bound SQLite read, in the original owner
`DomainStore.list_authorization_grants` source, can use:

```sql
SELECT g.*
FROM authorization_grants AS g
JOIN engagements AS e
  ON e.engagement_id = g.engagement_id
 AND e.client_id = g.client_id
WHERE g.engagement_id = ?
  AND e.client_id = ?
ORDER BY g.created_at DESC
```

Bind `(engagement.engagement_id, engagement.client_id)` from the
already-authorized engagement. The same *statement* now checks current
persisted engagement ownership, stored grant lineage, and the authorized
tenant; any intervening rebind to a different owner gives **no result**.
Preserve valid newest-first ordering, immutable storage and the
`get_current_grant` inheritance. For a stronger concurrent write threat
model, consider authorization and read in one transactional snapshot too:
this synthetic interleaving test is not an exhaustive live concurrency proof.

The source owner must independently review this proposal against other active
source-authority branches, including use of SQLite transactions and
whole-request revocation checks. No actual source owner code was committed.

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

## W3 — deterministic owner-rebinding interleave and stronger JOIN oracle

An additional **two** genuine temporary-SQLite source REDs simulate the
engagement owner changing A → B **after** the first authorized
`get_engagement` read but **before** the grant query. On original source
and on the earlier apparently sufficient `WHERE engagement_id=? AND
client_id=?` fix, stale A grants can still escape. This is a synthetic
controlled interleaving, not a proven real remote race exploit.

The independent isolated source-oracle has been upgraded to:
- original source **16 strict REDs** among **25 real methods**;
- fresh engagement JOIN and both exact owner equality bindings:
  **25/25 real SQLite + operator WSGI tests PASS** without expectedFailure;
- four deliberately weaker source changes (**cached tenant-only predicate**,
  `TRIM` matching, premature `LIMIT 1`, and current-grant-only filtering)
  all remain STRICT RED.

On exact W3 head `c97f8a9352da7017055f554c65023ffbf2a26166`,
connected zSSH Python 3.14.4 ran **31 methods** total, comprising
**15 ordinary PASS, 16 known installed-source expectedFailures**; no
unexpected success or unexpected failure. No production code, client
asset, live network endpoint, actual grant, handler or worker-owned file
was changed. The named self-hosted CI is not thereby certified.
