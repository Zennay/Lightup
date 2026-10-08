# Scope authorization: independent evidence-review checklist (M1)

Status: reviewer aid only; **not** a grant, signature, approval record, or production activation authorization.

## Purpose
A reviewer must be able to establish that a single proposed `TARGET_ACTIVE` decision is bound to an independently recorded human approval, an explicit immutable run snapshot, and current persisted authorization **without performing any live target interaction**. This document does not authorize tests or change policy.

## Non-negotiable release gate
- The real-target activation switch stays **off** throughout M1. Passing this checklist never turns it on.
- Use synthetic identities and loopback/in-memory fixtures only. Never place real customer tokens, credentials, target addresses, contact details, or full approval attachments into CI artifacts.
- Reviewer must be independent of the author of the authorization record for any future production activation.
- A dry-run verdict is advisory evidence, not an execution grant. No LLM answer or generated report is itself approval.

## Reviewer procedure
1. **Provenance** — identify operator, approving human, engagement and client through canonical persisted identifiers; reject self-approval and missing or unverified approver authority. Record immutable reference IDs, not personal data.
2. **Intent** — require the approval to explicitly name activity class, target inventory, exclusion list, risk ceiling, capabilities, validity start/end, and engagement. Reject ambiguous wildcard claims.
3. **Identity** — compare *typed* canonical identifiers and enum members; string-like or numeric stand-ins do not satisfy the contract. Match tenant, engagement, grant and run IDs exactly.
4. **Timeline** — verify creation, approval, revocation and dispatch ordering from trusted stored events. Treat malformed, naive, unavailable, or inconsistent clocks as deny; do not infer trust from timestamps alone.
5. **Scope intersection** — effective authority must be a subset of both the run snapshot and latest same-ID persisted grant. No target, capability, risk level or validity interval may expand after run creation.
6. **Revocation** — prove latest authoritative status is active at the final policy gate. Queued, retried and resumed executions must revalidate; a stale approval screenshot or cache is insufficient.
7. **Decision evidence** — ensure denial leaves handlers untouched and no target I/O happens. Persist the minimum nonsecret reason code and correlation IDs needed to reproduce the offline verdict.
8. **Reviewer verdict** — mark `PASS` only when each applicable row has a reproducible offline artifact. Otherwise `NEEDS_EVIDENCE` or `FAIL`; never mark production-ready from a doc-only review.

## Evidence table (fill in for review, do not commit populated customer details)

| Proof | Offline artifact / immutable SHA | Result |
| --- | --- | --- |
| Approver has separate verified authority | | PASS / FAIL / NEEDS_EVIDENCE |
| Explicit in-scope asset and excluded asset | | PASS / FAIL / NEEDS_EVIDENCE |
| Capability + maximum risk bound | | PASS / FAIL / NEEDS_EVIDENCE |
| Canonical same-tenant engagement/grant/run identities | | PASS / FAIL / NEEDS_EVIDENCE |
| Snapshot/live grant intersection | | PASS / FAIL / NEEDS_EVIDENCE |
| Trusted validity window and revocation state | | PASS / FAIL / NEEDS_EVIDENCE |
| Denials invoke no handler and no network | | PASS / FAIL / NEEDS_EVIDENCE |
| Evidence ledger append and retention policy | | PASS / FAIL / NEEDS_EVIDENCE |
| Real-target activation remains disabled | | PASS / FAIL / NEEDS_EVIDENCE |

## Offline negative-case matrix
For each scenario, assert **DENY + zero handler invocations + zero outbound requests**, and record exact fixture revision.

| Scenario | Expected |
| --- | --- |
| Unknown/absent approver or unverified authority | DENY |
| Same principal creates and approves request | DENY |
| Missing scope or capability intent | DENY |
| Asset explicitly excluded despite otherwise matching inventory | DENY |
| Requested risk higher than explicit ceiling | DENY |
| Wrong client/tenant/engagement/grant binding | DENY |
| Numeric/string stand-in instead of canonical enum/identifier | DENY |
| Grant revoked between scheduling and dispatch | DENY |
| Live grant widens snapshot authority or time window | DENY |
| Clock unavailable or approval not yet valid / expired | DENY |
| Missing canonical audit ledger or forged/swapped ledger | DENY |
| Trusted scoped grant, but M1 real-target activation disabled | DENY |

## Exit criteria and ownership
This document is an add-only, collision-free reviewer artifact. Implementation ownership stays with existing execution policy, grant storage, approval provenance and executor PR authors. A release owner may reference this checklist when all rows are backed by tested offline evidence and the applicable production PRs have passed CI. It cannot substitute for those proofs, legal permission or independent review. No live scanning, discovery, exploit code, deployment or policy widening is introduced here.
