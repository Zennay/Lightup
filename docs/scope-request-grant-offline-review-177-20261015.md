# LightUp scope-authorization #177 — offline request ↔ grant review

**State: INCUBATE M3/M7 • PLAN/LAB ONLY • DRAFT/HOLD. Not an authorization mechanism.**

## Why this exists

Current `DomainStore.record_authorization_grant` does not persist a foreign key to an
approved assessment request. A structurally valid `AuthorizationGrant` cannot
prove that the matching client actually obtained operator request approval.
Issue [#177](https://github.com/Zennay/Lightup/issues/177) remains **open**.

`src/lightup/request_grant_offline_review_177.py` is an **uninstalled, offline,
opt-in reference**, isolated from production source owners and other worker PRs.
It accepts two explicitly untrusted in-memory snapshots built from the actual
`AssessmentRequestRecord` and `AuthorizationGrant` classes plus a caller
supplied review instant. There is no network, DNS, database, clock read, mutation,
token, scan, or action on any customer system.

## Invariant matrix

| Gate | Explicit HOLD trigger |
| --- | --- |
| Types | non-exact request/grant/scope objects, impersonated strings or enum values, bool/int risk type confusion |
| Request approval | status other than exact `APPROVED`, mode other than `AUTHORIZED_ASSESSMENT`, no named operator, malformed request creation timestamp or decision timestamp; decision predates request creation |
| Tenant/provenance | mismatched request/grant client or grant approver vs request decider |
| Assets | grant target not *exactly* present in requested assets; blank, duplicate, mixed-case, non-canonical, URL/port/wildcard, Unicode or variant-IP spelling; excluded assets not among the granted set |
| Risk | grant risk above approved risk, destructive lab-only mode, malformed risk, empty wildcard capabilities (meaning unrestricted in the real model), unknown IDs, or LAB_ONLY/DISABLED IDs rather than canonical PLANNING capabilities |
| Time | decision in future, missing/invalid UTC decision, malformed, non-UTC-offset or naive grant times, hostile custom timezone object, grant precedes decision, grant not current at explicit review instant |
| Metadata | invalid excluded target/capability item collection; malformed recurring retest flag |

All identity fields also use a bounded (max 128 characters) ASCII identifier grammar with no whitespace or control characters. Empty allowed capability tuples are refused because the real ScopeDefinition interprets an empty allowlist as **unlimited tools**. The reviewer also requires a canonical request-created timestamp to precede the decision, strict built-in UTC timezone identity for supplied datetime objects, and a real high-level PLANNING-only capability ID from the currently installed catalogue. An approved assessment request has no independent recurring-retest approval flag, so `recurring_retest_allowed=True` is always HOLD. `valid_from == valid_until` is also HOLD: the real DomainStore disallows empty validity windows, and the offline reviewer must not contradict that invariant. The catalogue check does not authenticate the caller or any authorization.

The conservative **exact-string** comparison deliberately refuses aliases
instead of equating non-canonical host/IP representations. DNS names must be
lowercase ASCII labels with no trailing dot. IPv4 and IPv6 literals are
syntactically reviewed via standard-library `ipaddress`; no lookup occurs.
The reviewer does **not** prove whether assets belong to a customer, whether
a hostname resolves, whether a request belongs to an engagement, or whether
a declared approval is signed or persisted. Source-owner canonical scope
rules are authoritative; this toy format is only a strict offline reference.

## Atomic multi-request review (opt-in)

`review_request_grant_batch(pairs, reviewed_at=...)` accepts only an exact Python tuple of 1–32 exact two-tuples of untrusted request/grant snapshots, all on one declared client. Every member must already be structurally REVIEW_ONLY using the single-grant reviewer. Duplicate request IDs, duplicate grant IDs, effective granted-asset overlaps, mixed tenants, malformed entries and input above the limit cause a single **atomic HOLD**. No per-item status, no granted asset/client ID, no partial acceptance. A completely coherent batch remains **REVIEW_ONLY with all six false flags**. Excluded assets are not treated as effective scope membership during overlap checking; overlapping claims without actual granted membership are still not permission. The batch performs no I/O or issuing step and is **not** a release authority.

## Three-way engagement lineage review (opt-in)

`review_request_grant_engagement(request, grant, engagement, reviewed_at=...)`
additionally inspects an **untrusted snapshot** of the real `EngagementRecord`.
It requires exact built-in `EngagementRecord`, exact declared
`EngagementStatus.AUTHORIZED` (DRAFT/RUNNING/CLOSED do not count as approval),
exact matching grant engagement ID, identical client on all three objects, and
canonical UTC engagement creation before the declared grant start. Type-confused
grant windows and malformed engagement timestamps atomically HOLD.
A coherent engagement snapshot still cannot establish an authenticated link
from the original assessment request to that engagement: the current domain
schema has **no such request FK**. The result remains `REVIEW_ONLY`, all
six authority flags false, with zero persistence or operational side effects.
Only source-owner implementation of a real durable request→grant→engagement
chain can resolve issue #177.

## Atomic composed 3-way review

`review_request_grant_engagement_batch(entries, reviewed_at=...)` composes
both strictly offline checks. It accepts an exact tuple of **1–32 exact
three-tuples** (request, grant, engagement). It refuses any invalid three-way
engagement lineage before applying the single-tenant, duplicate request/grant ID
and effective target-overlap checks to the **entire** group. Malformed
container types, duplicate records, mixed clients, one revoked/draft engagement,
unknown asset, risk escalation or a 33rd record are all an **atomic HOLD**.
Thirty-two distinct entirely synthetic, coherent records are still
`REVIEW_ONLY` only, with all six authority flags literally false. No
persistent cross-record linkage, consent, dispatch or trusted grant is created.

## Results and hard boundary

- `HOLD`: malformed or incoherent untrusted snapshots.
- `REVIEW_ONLY`: their declared shapes are mutually coherent but **not
  independently verified**. **Not PASS.**
- **Both** outcomes have exact literal `False` for `authorized`,
  `grant_allowed`, `dispatch_allowed`, `scan_allowed`,
  `merge_allowed`, and `deploy_allowed`. The receipt contains only
  fixed, non-customer-specific reasons. The frozen/slotted receipt constructor now rejects spoofed `True` / truthy-ish / non-boolean authority flags, forged status strings or mismatched reasons; callers cannot construct a normal positive receipt through the public API. **This is not a cryptographically authenticated receipt and an adversarial in-process Python interpreter can still alter objects through reflection.** No runtime component should ever treat it as an authority. Nothing is installed into grant
  persistence, `ActivationGate`, `ScopePolicy`, `ToolExecutor`, or web ingress.
- Under **no circumstances** should `REVIEW_ONLY` be converted into a grant,
  permit, approval, dispatch, release, or CI PASS.

## Read-only persisted SQLite proof (opt-in; synthetic migration only)

`src/lightup/request_grant_sqlite_preflight_177.py` adds
`review_persisted_request_grant(local_database_path, grant_id, reviewed_at=...)`.
This API makes **only read-only** SQLite queries against a deliberately chosen
local file; it opens `mode=ro` + `query_only=ON`, verifies a real table (not a
view), uses a single transaction snapshot and always closes the connection.
It never creates a database or grant and never emits customer data, an
authenticated permit, permission to contact a host, or a release decision.

Current `main` does not have `authorization_grants.approved_request_id`
or a declared foreign-key reference to
`assessment_requests(request_id)`. Consequently, it can **only return HOLD
for a normal unmodified LightUp database** even when the submitted request and
grant happen to match by customer or target. Adding a same-named plain text
column without an actual SQLite FK is **still HOLD**: self-asserted strings
are not a trustworthy durable authorization chain.

In a disposable test database **only**, a hypothetical explicit FK migration
can be simulated with `ALTER TABLE authorization_grants ADD COLUMN
approved_request_id TEXT REFERENCES assessment_requests(request_id)`.
**W10 chronology and FK integrity:** The persisted grant record must also
have been created **on or after engagement creation** and **on or before
its own `valid_from`**. Retroactively activating a permission interval before
the durable grant existed is a structural HOLD even if the requested risk,
request approval and proposed assets otherwise match. Exact equality between
grant recording and validity start is acceptable *only* as untrusted
REVIEW_ONLY evidence.

The provenance FK must be an **independent single-column** constraint to
`assessment_requests(request_id)`; a composite FK with
`approved_request_id` merely appearing as its first column is **not**
acceptable. `PRAGMA foreign_key_check(authorization_grants)` additionally
checks for orphan records written by other SQLite connections that disabled
FK enforcement. Any broken dependent grant in the table atomically makes the
optional review HOLD, including when the specifically selected grant is valid.
This offline scan can be expensive for large local databases, so it is neither
installed nor appropriate as a live dispatch path. Both opt-in SQLite readers
now have a **per-connection VM progress budget** (2,000,000 approximate
virtual-machine instructions); intentionally pathological or oversized
read-only queries interrupt and return the same privacy-safe HOLD. Real
disposable two-grant snapshots remain reviewable. The batch checks the
global FK table **once per immutable read transaction**, not once per grant,
but rechecks it again on the next independent review. A clean SQLite
snapshot is still not signed permission or evidence of genuine customer
consent.

The synthetic acceptance suite creates real `DomainStore` customers,
approved requests, engagements and grants with SQLite, then independently
mutates submitted status/mode, tenant, grant scope/capabilities, timestamp,
retest flag and linkage to prove denial and row immutability. A perfect
synthetic FK + self-consistent triple is **still REVIEW_ONLY** with all six
authority fields exactly `False`.

Two additional chronology/independence invariants are pinned by genuine
SQLite negative tests: the requester must not be the same identity as the
operator who recorded the approval (self-approval is not an independent
decision), and the stored grant `created_at` must be a canonical UTC instant
on or after the persisted request `decided_at` and no later than the explicit
read-only review instant. A later `valid_from` window can no longer hide
a grant record inserted before approval. Malformed/offset grant-creation
timestamps also HOLD. Neither safeguard proves the human's real identity
without external authenticated provenance.

**Important boundaries:** A declared FK and a read-only DB snapshot are
*not* independent proof of customer consent, signer's identity, immutable
operator decision or present-day revocation. Fake schemas can be fabricated,
and the result is not signed; this code must never be installed as the
authoritative admission path. Actual source-owner work still needs a real
migration, correct ownership of risk and permission lifecycle, independent
authorization controls before every active dispatch, security/privacy
review, permanent VPS evidence and explicit human release.

Run real disposable SQLite acceptance with:

```sh
python -m unittest discover -s tests -p 'test_scope_request_grant_sqlite_preflight_177.py' -v
```

### W12: never reuse one approved request across stored grant records

A valid SQLite foreign key only shows that a target *exists*; it does not
prove that the same approval was not spent on another grant. The opt-in
single-grant reader now checks **all persisted authorization_grants** for
any *second grant ID* with the **same approved_request_id**, whether or
not that other grant was included in the reviewed batch. It returns
generic `HOLD` even when the additional grant is expired or otherwise
unrelated, because the current schema lacks authenticated amendment,
replacement, revocation, or reusable-consent provenance. The batch reader
inherits the same restriction for every member. This check intentionally
treats a normal SQLite FK relationship as **necessary but insufficient**;
the separate global `foreign_key_check` cannot spot duplicate approval
reuse because both dependent rows may legitimately reference the same
existing parent.

Real isolated `DomainStore` SQLite regressions prove two distinct,
valid approved requests are only `REVIEW_ONLY`, then replace the second
grant's request link with the first approved request and prove a solo
review of either grant and a one-grant batch switch to `HOLD` without
the FK-check detecting any orphan. This is deliberately uninstalled
and never a grant, consent record, or production database migration.
Source-owner follow-up: enforce stable request→grant cardinality or
design signed, immutable explicit amendment/retest approvals with a
proper migration and atomic uniqueness constraints.

## W15: full-table tenant and operator lineage, including unrelated tenants

A declared `approved_request_id REFERENCES assessment_requests(request_id)`
FK verifies only **row existence**, not that the grant's `client_id`,
its engagement's client and its approved request's client all agree, or
that `approved_by` is the independent requester-review decision-maker.
The optional local viewer now performs a bounded, **read-only left-join
audit of every stored grant** in the same immutable SQLite snapshot,
enforcing exact canonical identity, one tenant across request/grant/
engagement, matching decision operator, independently signed request
(requester != reviewer), real APPROVED status, AUTHORIZED_ASSESSMENT
mode and AUTHORIZED engagement state. It also checks strict UTC chronology
for each stored grant: request creation <= independent decision <= grant
persistence <= declared validity start < validity end, with engagement
creation no later than grant persistence. A malformed child in an
*unselected other tenant* yields global
HOLD rather than a false claim that this local provenance dataset is clean.
The same audit runs once per batch transaction and again on the next
independent snapshot; the SQLite VM budget remains active.

Real disposable `DomainStore` SQLite tests create a genuinely separate
second synthetic client/engagement/approved request and verify it does
not interfere with the first client's `REVIEW_ONLY` structural preview.
They then tamper the *other tenant* client, engagement, approver, requester,
decision, status, mode, creation/approval/grant timestamps or the declared
window without breaking SQLite's native FK and require the single and batch
readers both to return HOLD. This is a **conservative
whole-database health preview**, never a multi-tenant live permission
oracle. Source-owner must actually bind tenant, engagement and decision
by authenticated transactional production constraints.

### W15 sibling grant policy and exclusion validation

A neighboring same-tenant grant's exclusion list must itself be an exact
unique subset of the grant's canonical assets. Without validating it, a
forged `excluded_assets_json` could make a conflicting target disappear
in a set subtraction. The read-only reviewer now also validates each
neighbor's canonical bounded asset IDs, exact nonduplicate exclusion
membership, known PLANNING-only capability IDs, risk enum (not destructive
lab-only), and no independent recurring-retest claim. Invalid sibling
metadata makes the selected solo review and any associated one-ID batch
HOLD. Tests cover malformed exclusions, duplicates, foreign assets, empty
or duplicate claimed assets, invalid capabilities, destructive risk, and
retest opt-in; a well-formed fully excluded neighbor still cannot authorize
anything and is allowed as `REVIEW_ONLY` evidence for the other grant.

## W14: require a request FK value on every stored grant

SQLite `REFERENCES` is not the same as `NOT NULL REFERENCES`: a nullable
`approved_request_id` child is considered **valid** by SQLite's normal
`PRAGMA foreign_key_check` even when it has **no approved request at all**.
This was a separate omission in global provenance review because one valid
selected grant could coexist with an unselected NULL-linked grant. W14
now scans the complete child table for **exact canonical, nonempty approval
references** under the same bounded read-only transaction, then performs
the real SQLite FK consistency scan. Any NULL, malformed or unlinked
grant yields one global `HOLD`, regardless of which row was requested.

Disposable in-memory and actual temporary `DomainStore` SQLite tests prove
that SQLite itself reports **zero FK violations for NULL child rows**, yet
both our single-row review and one-grant batch now **HOLD** when another
unreviewed grant contains NULL. Additional in-memory tests prove that even
a **non-NULL, syntactically invalid reference** (such as one containing a
slash) may point to an existing parent row and pass SQLite's native FK
check; our strict canonical request-ID grammar still requires HOLD. This does *not* change, migrate or delete
any production data. Source-owner production migration should use
`approved_request_id NOT NULL` and an authenticated, immutable,
transactional binding with suitable uniqueness/revision constraints.

## W13: detect hidden concurrent same-target grants in single-record review

A caller can omit conflicting grants from a requested batch, and the real
`DomainStore.get_current_grant` does not establish authenticated priority
between overlapping persisted grants. A single read-only review therefore
scans **other stored grants for the same client** in the same SQLite snapshot.
When two granted **effective assets** overlap *and their declared UTC validity
intervals overlap*, **both single-grant reviews HOLD**. This remains true
when their approved request IDs are different and all foreign keys are valid.
Malformed same-client neighboring grant windows/asset JSON also HOLD rather
than silently skipping evidence that could hide a conflict.

The review distinguishes harmless cases: a second grant for a disjoint
asset is allowed as structural REVIEW_ONLY, a matching asset excluded in
the other grant does not count as active, and a future **non-overlapping**
validity interval does not conflict. Independent disposable SQLite tests
exercise those boundaries. The progress-handler VM budget bounds the
additional scan. This is only an offline conservative metadata review,
NOT an installed conflict scheduler, expiration/revocation enforcement,
or permission to choose one grant for target interaction. The source
owner must define authenticated supersession/amendment policy before any
real dispatch can use overlapping grant histories.

## Atomic persisted batch, same read snapshot

The second optional API `review_persisted_grant_batch(local_database_path,
grant_ids_tuple, reviewed_at=...)` evaluates **1–32 distinct exact grant IDs**
in **one** SQLite read transaction. Each persisted grant must independently
pass FK/schema/request/engagement/asset/risk/calendar checks before a **global**
tenant and effective-target-overlap review. A duplicate ID, one unknown grant,
duplicate approved-request ID, mixed client, overlapping effective asset, or
33rd entry returns one fixed, privacy-safe `HOLD` for the **entire** batch.
Separate per-grant reads can observe different database versions, so the
shared-transaction batch is the safer read-only evidence *preview*, not a
live grant gate. Neither outcome supplies permissions, even when two
isolated synthetic records and both declared FKs are structurally coherent.

The tests create two real disposable SQLite grants, plus two separately
authorized synthetic tenant records, and confirm atomic HOLD on cross-tenant
and overlapping assets. A before/after SQLite row comparison and no-socket
tripwire verify lack of side effects. The current production schema still
cannot pass because there is no approved-request FK.

Do **not** run this opt-in reviewer on a real customer database without
separate permission to process those local records. It performs no outbound
traffic, but reading sensitive records still requires authorization.

## Real producer RED contract (source owner outstanding)

Six **intentional** `unittest.expectedFailure` canaries now invoke actual
`DomainStore.record_authorization_grant` in disposable SQLite databases
and demand a fail-closed exception when (a) the tenant has **no approved
assessment request**, (b) the granted asset **exceeds** the only approved
request, (c) the grant's named approver is **not** the decision operator,
(d) the only matching request was explicitly **rejected**, or (e) an\noperator attempts to **approve their own submitted request** through real\n`DomainStore.review_assessment_request`. Today all five
demonstrate unresolved issuance/approval bypasses as **expected RED**, never as a
passing security invariant. They are not fixtures for real clients.

The independent source owner must implement the genuine persisted request
FK and denial guards, then convert these intentional expected failures into
ordinary passing negative tests. A green CI suite containing these expected
failures **does not mean live issuance is secure**. Runtime authorization
and revocation/destination controls remain separate release gates.

## Required production integration (not done here)

An independent source owner must implement durable approved-request linkage
on the same client **and engagement**, review decision persistence, immutable
operator provenance, exact canonical asset subset, approved mode/risk, current
grant + revocation checks on each active operation, and audit trail consistency.
Security/privacy review, current operator/customer consent, exact-head hosted
CI and separate registered permanent-VPS proof, then explicit human merge and
deployment authorization are required before a real active path can be enabled.

## Test

Offline synthetic fixtures only; real Python 3.11/3.14 CI validates single/batch denial, catalog and exact UTC isolation:

```sh
python -m unittest discover -s tests -p 'test_scope_request_grant_offline_review_177.py' -v
```

The acceptance suite checks approved narrowing, invalid status, mode, tenant,
approver, assets, risk, timeline, metadata, polymorphic identities, output
redaction, no-network property, and inclusive **non-authorizing** time bounds.
All fake client and asset names are fixed fixtures; no target traffic or real
credential is accessed. Passing these tests **does not close #177**.
