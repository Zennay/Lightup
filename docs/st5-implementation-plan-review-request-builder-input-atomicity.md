# ST5 implementation-plan review-request builder input atomicity

This acceptance slice is a tests/docs-only child of the active implementation-
plan review-request producer in #278.

## Invariant

`build_future_remediation_implementation_plan_review_request` must be a pure
review-intent boundary over a strict live-valid implementation-plan lineage.

The regression proves that:

- repeated successful construction returns the exact same canonical request;
- persisted implementation plan, implementation-planning request, remediation
  review, review request and proposal remain unchanged;
- caller-owned authoring/evidence/plan/report/graph/transition/context lineage
  remains unchanged;
- live evidence state remains unchanged;
- the builder never creates runs, acquires leases, appends evidence or invokes
  a model;
- live evidence SHA drift rejects deterministically on repeated calls without
  mutating stale state or any caller-owned input.

## Authority stop line

A successful result may set only
`implementation_plan_review_requested=true`.

The implementation plan remains unaccepted and all code-change, tool-call,
execution, target-interaction, future-state-retest, deployment and attack-path
mutation authority stays false. Future semantics remain `unresolved` and the
security verdict remains `not_evaluated`.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #278 source or existing tests/docs, #280 handoff work, #281 reviewer
work, snapshot/schema owners, scope authorization, provider behavior,
target-capable code, remediation execution or retest execution.
