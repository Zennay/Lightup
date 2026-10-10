# Evidence-remediation review queue — isolated M3/M7 advisory (2026-10-10)

## Why this lane exists

Current LightUp evidence and remediation work has multiple concurrently owned stages:
durable finding evidence (#851/#856/#883–#894), AI review (#841/#845/#898–#902),
historical retest transition preflight (#1176), retest lineage (#1065–#1078).
No independent, bounded **review-only worklist** exists for the already selected
real `FindingRecord` objects while source owners integrate those gates.

This isolated producer does **not** integrate with the persistence layer or
the live API. It introduces a deterministic advisory queue without changing
any other worker's code.

## Contract

`build_remediation_review_queue(tuple_of_finding_records, client_id=..., engagement_id=...)`:
- exact built-in record, enum, tuple and identifier types; strict same-scope
  consistency; 128 findings / 64 unique evidence references per finding;
- severity-first review priority (critical before high before lower severities);
- zero evidence: `collect_evidence`; evidence but missing fix text:
  `author_remediation`; regression claim: `investigate_regression`;
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

The output schema is `lightup.remediation_review_queue.v2`. In v1 the queue
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

## Explicit non-authority and collision fence

The caller must first perform authenticated tenant-specific selection.
The helper trusts neither its `client_id` argument nor its input records as
an authorization grant. A matching field is only a structural consistency
check. It never queries SQLite, issues requests, calls AI/verification tools,
reads raw evidence files, contacts targets, executes remediation, records retest
results, creates risk approvals, changes security-twin or CI verdict state, or
claims production integration.

No modifications to owners' source paths:
`domain.py` (#828/#851/#856),
`labsync.py` (#184/#854), review pipeline (#841/#846),
current finding retest preflight (#1176), or scope executor (#107).
All changes are four add-only files on immutable `main=dd4072c`.

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
