# ST5 implementation-plan reviewer producer input atomicity

This acceptance slice is a tests/docs-only child of the active bounded
implementation-plan reviewer in #281.

## Invariant

`review_future_remediation_implementation_plan` may perform one bounded
VERIFIER call after strict live validation, but it must not mutate any
caller-owned persisted/live lineage or StateStore state.

The regression proves that:

- two independent verifier gateways returning the same decision yield the exact
  same canonical review;
- persisted review request, implementation plan, planning request, remediation
  review, remediation review request and proposal remain unchanged;
- caller-owned authoring/evidence/plan/report/graph/transition/context lineage
  remains unchanged;
- live evidence state remains unchanged;
- the reviewer never creates a run, acquires a lease or appends evidence;
- successful review performs exactly one model request per gateway;
- live evidence drift rejects deterministically on repeated calls before any
  verifier request and leaves stale state plus all caller-owned inputs intact.

## Authority stop line

An approved review may set
`implementation_plan_review_completed=true` and
`implementation_plan_accepted=true` only.

It must not grant code-change, tool-call, execution, target-interaction,
future-state-retest, deployment or attack-path-mutation authority. Future
semantics remain `unresolved` and the security verdict remains
`not_evaluated`.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #281 source or existing tests/docs, #283 handoff, #284 revision-request,
snapshot/canonicality owners, scope authorization, provider implementation,
target-capable code, remediation execution or retest execution.
