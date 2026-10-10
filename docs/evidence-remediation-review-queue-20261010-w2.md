# Evidence-remediation review queue — isolated M3/M7 advisory (2026-10-10)

## Why this lane exists

Current LightUp evidence and remediation work has multiple concurrently owned stages:
durable finding evidence (#851/#856/#883–#894), AI review (#841/#845/#898–#902),
historical retest transition preflight (#1176), retest lineage (#1065–#1078).
No independent, bounded **review-only worklist** exists for the already selected
real `FindingRecord` objects while source owners integrate those gates.

The pure review builder never queries persistence. An **opt-in,
read-only** adapter separately reads an authorized single engagement through
`DomainStore`; neither component is connected to the live API or changes
any other worker's code.

## Contract

`build_remediation_review_queue(tuple_of_finding_records, client_id=..., engagement_id=...)`:
- exact built-in record, enum, tuple and identifier types; strict same-scope
  consistency; 128 findings / 64 unique evidence references per finding;
- severity-first review priority (critical before high before lower severities);
- zero evidence: `collect_evidence`; evidence but missing fix text:
  `author_remediation`; format-control / zero-width / combining-mark /
  punctuation- or emoji-only "remediation" also remains
  `author_remediation` (no letter/number, including non-Latin scripts).
  Human-authored Unicode letters/numbers are counted as text presence,
  never trusted as proof of a fix; regression claim: `investigate_regression`;
  status `fixed`: `independent_retest`; everything else:
  `review_remediation`;
- no inference that `fixed` means retested, externally verified, safe to
  deploy or authorized for any interaction. All authorization and verification
  fields are literally false;
- output excludes raw target URLs, evidence references, remediation content,
  client/engagement IDs, titles, impact, timestamps, and secrets. It emits
  an SHA-256 pseudonymous correlation key and canonical, source-bound snapshot digest,
  **not** a proof of tenant ownership or evidence provenance.
- deterministic input-preserving JSON, fail-closed on duplicate IDs, malformed
  references, cross-tenant/engagement input and oversized records.

A simple SHA-256 pseudonym is **not anonymization** and may be brute-forced
if source identifiers have low entropy. Do not publish review keys outside
an already authorized tenant-scoped workflow. Counts can also disclose activity.

## V2 snapshot integrity and privacy boundary

V2 historically introduced a source-bound digest (now superseded by
the current `lightup.remediation_review_queue.v4` schema). In v1 the queue
digest depended only on visible review fields and *counts* of referenced
evidence. Swapping evidence A for evidence B while preserving the same count
and review step produced exactly the same digest, as did rewriting a fix.
That structural digest was not suitable as an advisory snapshot change token.

V2 now binds the root digest to the explicit client/engagement context
(including when there are zero findings) and a domain-specific SHA-256
fingerprint of each full source record: ordered evidence IDs, remediation
text, title, asset, impact, created_at, severity, claimed retest status and
finding identity. Item presentation still omits all raw source fields.
Sorting remains independent of input row order, and any source edit changes
the review-snapshot digest even when the visible advisory stays identical.

**Limitations:** This digest is deterministic and not keyed or authenticated.
It does not establish origin, completeness, genuine evidence, successful
remediation, tenant rights or tamper resistance against an adversary able
to recompute the digest. Low-entropy source values may still be guessed
from digest comparisons. Only use inside an authorized trusted tenant flow.
Do not use this hash as an authorization, audit-log signature, independent
retest certificate, or public privacy/anonymization claim.

## V3 unambiguous finding identity correlation

V2's pseudonymous per-item `finding_key_sha256` was SHA-256 over
`"lightup-review-v1\\\\0" + client_id + "\\\\0" + engagement_id + "\\\\0" + finding_id`.
The two-character printable sequence `\\\\0` was allowed inside all
three IDs; different scope/ID tuples could therefore serialize to the
same concatenated bytes and accidentally share a pseudonymous key.
The root review digest was scope-bound already, but cross-tenant item-key
collisions are not acceptable even in an advisory.

V3 uses canonical JSON of a **four-element typed identity tuple**:
`("lightup-review-finding-key.v3", client_id, engagement_id, finding_id)`,
then SHA-256. JSON serialization preserves component boundaries, and
separate engagements cannot reuse the same item key merely by injecting
the old delimiter into a printable identifier. Dedicated synthetic
regressions construct an exact former collision and prove distinct keys.
The original v3 release made incompatible fingerprint semantics visible
instead of silently reusing the v2 digest. The **current v4** payload and root
digest additionally bind the complete ordered human-review action list.

This is still only a deterministic pseudonym, not anonymization,
authorization, proof of data provenance, or a MAC/signature. Do not
publish low-entropy identifiers or their deterministic hashes externally.

## Optional read-only DomainStore source

`read_remediation_review_queue(store, context, engagement_id=...)` in
`src/lightup/remediation_review_source.py` is an **opt-in adapter**, not an
application or web entrypoint. It demands an exact `DomainStore`, an exact
`AccessContext` created by a separately authenticated trusted caller, and an
explicit bounded engagement selector (including for operators).
The adapter now performs the same **AccessContext.resolve_client** tenant
admission used by `DomainStore.get_engagement`, but **inside the same
explicit `BEGIN` / `ROLLBACK` SQLite snapshot** as the selected
engagement and its finding/evidence rows. This removes a former
authorization/data consistency gap: an engagement could change tenants
between the separate access-check connection and the finding snapshot.
No separate `get_engagement` or legacy `list_findings` connection is
called.

A concurrent WAL writer can still commit a reassignment, but a single
review sees the original tenant and source data from the same snapshot.
A subsequent read sees the new tenant and denies the old client. This is
**snapshot-consistent tenant matching**, not proof the caller was actually
authenticated, not consent to test, and not a guarantee of post-read
revocation. Only trusted application session construction can supply
real identity and authority. Unknown engagement selectors fail with a
generic non-revealing `ValueError`; cross-tenant access retains
`TenantIsolationError` without source identifiers in the message.

Existing `DomainStore._finding_from_row` may parse legacy persisted
`evidence_ids_json` objects by iterating their keys and may throw generic
`JSONDecodeError`/`TypeError` for corrupt input. Until owner #828/#856
replaces this decoder, the adapter inspects each finding's raw JSON
**inside the same read transaction** before invoking the legacy row
constructor, insisting on canonical arrays of built-in strings, and
bounding the query at 129 rows (accepting at most 128), 64 evidence
references per row and 16,384 JSON characters. **The SQL projection now
applies `substr(column, 1, MAX+1)` to every decoded source column before
Python allocates a row:** finding/scope IDs and enums 129 characters, source
text/timestamps 8,193 characters, raw evidence JSON 16,385 characters.
If a value exceeds the allowed budget, the extra character makes the
existing size check fail closed; the oversized full field never needs to be
materialized by Python. This does not bound SQLite's internal read/sort
workload or replace system-level DB resource controls. Source parsing and
ordinary `sqlite3.DatabaseError` storage failures are reduced to a generic
advisory integrity `ValueError` (without leaking DB schema/path details);
the module does not repair or migrate its input database. It verifies every row's
tenant/engagement identity and raw-versus-decoded tuple, refusing any
partial review result when one record is corrupt. Malformed data yields
the generic `ValueError("remediation evidence read integrity invalid")`
with no raw stored bytes in the exception. The transaction is always
rolled back; it does not migrate or repair data.

This is only a defensive *read-side adapter*. Tenant matching and
the finding/evidence snapshot are internally consistent; **session
authentication and revocation remain external and non-atomic** to this read.
Other code can mutate state immediately after returning. This does not prove
consent, real session provenance, evidence truth, remediation or retest
verification. Production still requires the owner-controlled canonical
decoder fix (#856/#886), trusted session provenance, action-time revision/
revocation checks and independent privacy/security acceptance. This module
cannot issue grants, contact targets or update durable finding/retest status.

Dedicated offline integration:
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_remediation_review_source_20261010_w2.py' -v`.
All test databases are disposable and local. Its checks include a
**concurrent WAL writer regression** (one read sees exactly one historical
revision, the next sees the new one), a **WAL tenant-reassignment regression**
(the first read only uses its original tenant-snapshot identity, and a second
read from the former tenant is denied), a regression proving neither separate
`get_engagement` nor `list_findings` is called, corrupt legacy JSON,
oversized row budgets, mixed-tenant denials and no evidence writes on rejection.

## V4 overlapping review obligations (no executable actions)

The historical v3 `next_review_step` priority is intentionally preserved.
Previously, a finding with missing evidence AND missing remediation AND a
regression claim would show only `collect_evidence`, hiding two important
human-review obligations. Schema `lightup.remediation_review_queue.v4` now
exports an **ordered `review_actions` list** in each item, in addition to the
unchanged `next_review_step`. Multiple independent obligations remain
visible: `collect_evidence`, `author_remediation`, `investigate_regression`,
`independent_retest`. When none applies the sole action is
`review_remediation`. Only immutable enumerated human-review hints are
accepted; duplicate or unknown actions, inconsistent priority, and attempts
to treat `review_remediation` as an extra authorization step fail closed.
The item constructor also refuses omissions or inventions of action needs
that can be inferred from its own fields: zero evidence must carry
`collect_evidence`, a `FIXED` claim must carry `independent_retest`, a
`REGRESSION` claim must carry `investigate_regression`, and those
actions cannot appear without their corresponding conditions. The presence
of meaningful remediation prose is not in the public item, so its missing-
text obligation is still computed only by the trusted builder (neither
approach is evidence authenticity or a consent check).
The queue digest includes the ordered action list and the revised schema,
so V3 hashes are not silently reused. The action list contains no raw
remediation, target or evidence reference IDs and **cannot execute
anything**. It does expose human-review needs such as missing evidence or a
claimed regression, so the summary and its deterministic pseudonyms must stay
inside a trusted tenant-scoped interface rather than public logs.

### Read-only engagement workload summary

`RemediationReviewQueue.review_action_counts` is an **immutable, in-memory
tuple of action-name/count pairs**, ordered by the same deterministic review
priority. It counts **each human obligation**, not just the primary step:
one finding with three independent blockers contributes to three counts.
For example a two-finding queue can have three or four required human tasks.
The counts do not represent completed remediation, authentic evidence,
verified fixes, task execution permission or release approval, and the
serialized JSON remains unchanged (v4). Empty queues return an empty tuple.

These counts reveal tenant workload/status and must remain inside a trusted
engagement-scoped interface; they are not safe for public telemetry or
unauthenticated dashboards.

### Real persistent-record and state-matrix acceptance

Dedicated temporary-`DomainStore` integration verifies a **critical real
finding** with simultaneously missing evidence, missing remediation and
`REGRESSION` yields all three human review obligations, ordered by the
same primary priority, without persisting changes or leaking private source
fields. A separately recorded `FIXED` claim with both inputs missing keeps
`independent_retest` explicitly in the list and every verified/authorized
flag false. Pure queue tests exercise **every `RetestStatus` value × evidence
present/absent × remediation present/absent**, ensuring a missing first input
never suppresses a later independent review requirement.

The adapter and queue remain separate, opt-in and **not wired into any
production route or security-gate decision**.

## In-memory view-model and SQLite read-only safety

The two immutable dataclasses now check their own constructor invariants:
`RemediationReviewItem` denies any positive evidence/fix/authorization
flag, invalid review stage, malformed pseudonymous key or out-of-range
evidence count. `RemediationReviewQueue` denies positive authorization,
retest, release or evidence flags, malformed digests, duplicate items and
noncanonical item types. These fail even with direct dataclass construction
or `dataclasses.replace`, instead of relying exclusively on the builder.
A frozen dataclass and SHA-256 fingerprint are **not authentication**; hostile
Python code can still mutate or fabricate objects and must never be treated
as an authority source. Only real independently verified session/consent
and durable evidence can grant anything.

The opt-in database adapter additionally sets `PRAGMA query_only=ON` on its
own temporary SQLite connection before `BEGIN`. This denies accidental
SQL writes on the review connection at SQLite level; `ROLLBACK` still runs
on both successful and rejected reads. Tests deliberately attempt an
`UPDATE` from inside row decoding and verify SQLite refuses it, while the
read-only review succeeds with zero row mutation.

## Malformed evidence and digest-version rejection fences

The selected finding's raw evidence must begin as a JSON array. Object,
scalar, missing-envelope and deeply nested recursive JSON cannot escape as
unhandled decoder tracebacks or be mistaken for accepted evidence; on this
read-only path the caller receives a generic integrity `ValueError` and
the corrupted database row is unchanged. The adapter still delegates the
canonical global decoder fix to source owner #856/#886. This local negative
case is **not** evidence provenance verification.

The serialized review version and root digest both reference a single
`REVIEW_QUEUE_SCHEMA_VERSION` constant; a later schema change must alter
the digest and export version together. Dedicated offline tests cover
that paired change without claiming authenticity or permission.

## Canonical access-context structure (not authentication)

Before opening SQLite, the opt-in reader now rejects non-enum role values,
blank/nonprintable/oversized subject IDs and polymorphic, unbounded or
whitespace-ambiguous tenant client IDs. This closes a local footgun in which
an `AccessContext` constructed with the string `"client_member"` (rather
than the exact `Role.CLIENT_MEMBER` enum) could accidentally be treated as
a client member by domain structural checks. Real `Role.CLIENT_ADMIN`,
`Role.CLIENT_MEMBER` and `Role.OPERATOR` contexts remain accepted when
their fields are canonical. No raw identity is included in rejection errors.

**These checks do not authenticate any user or prove client consent.**
Even a perfectly typed `AccessContext` is a forgeable Python object; only
a trusted session/token authority and action-time revocation can justify
any live operation. The advisory remains read-only and non-authorizing.

## Client engagement-existence non-disclosure

For a client-scoped `CLIENT_MEMBER` or `CLIENT_ADMIN`, both an unknown
engagement selector and a real engagement owned by another tenant produce
the **same `TenantIsolationError` and generic string**. This avoids making
the advisory reader an oracle for whether another customer's engagement
exists. An operator (already separately authenticated by its trusted caller)
continues to get a generic `ValueError("remediation review engagement not
found")` for nonexistent selections. In either case, the adapter reads no
cross-tenant finding rows or evidence and issues no data writes. Dedicated
temporary-SQLite tests compare both client denial paths.

## Explicit non-authority and collision fence

The pure queue builder requires authenticated tenant-specific selection.
The opt-in adapter only reads a selected engagement in temporary/opt-in domain
storage and cannot authenticate a self-asserted AccessContext. Neither API
trusts caller identifiers as an authorization grant. A matching field is
only structural consistency, not consent. Neither issues requests, calls AI/verification tools,
reads raw evidence files, contacts targets, executes remediation, records retest
results, creates risk approvals, changes security-twin or CI verdict state, or
claims production integration.

No modifications to owners' source paths:
`domain.py` (#828/#851/#856),
`labsync.py` (#184/#854), review pipeline (#841/#846),
current finding retest preflight (#1176), or scope executor (#107).
All changes are six add-only files on immutable `main=dd4072c`.

## Proof and serialized integration gate

Offline test: `PYTHONPATH=src python -m unittest tests.test_remediation_review_queue_20261010_w2 -v`.
Require native hosted LightUp offline preflight on the final exact SHA and
independent review before integration. The canonical LightUp self-hosted
runner currently has **zero registrations for this repository**, according to
the 2026-10-10 Notion/VPS handoff; indefinitely queued VPS jobs are NOT proof.
Do not merge or deploy solely from hosted preflight.

Before any future production consumer wiring: include trusted tenant/session
authorization, canonical durable-read guards, strict evidence identity/lineage,
independent retest proof, and privacy/export review. Maintain lab/plan-only
posture, no active targets and no external network interaction.
