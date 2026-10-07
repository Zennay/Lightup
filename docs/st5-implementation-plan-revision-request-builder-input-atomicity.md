# ST5 implementation-plan revision-request builder input atomicity

This acceptance slice is a tests/docs-only child of the active bounded
implementation-plan revision-request producer in #284.

## Invariant

`build_future_remediation_implementation_plan_revision_request` must be a pure
planning-metadata boundary over a strict live `revision_required`
implementation-plan review.

The regression proves that:

- a canonical revision-required review with only `rollback_sufficiency`
  failing produces the same deterministic revision request on repeated calls;
- persisted plan review, plan review request, implementation plan, planning
  request, remediation review, remediation review request and proposal remain
  unchanged;
- caller-owned authoring/evidence/plan/report/graph/transition/context lineage
  remains unchanged;
- live evidence state remains unchanged;
- the builder never creates runs, acquires leases, appends evidence or invokes
  a model;
- live evidence SHA drift rejects deterministically on repeated calls without
  mutating stale state or any caller-owned input.

## Authority stop line

A successful result may set only
`implementation_plan_revision_requested=true`.

It must keep `revised_implementation_plan_created=false`,
`implementation_plan_accepted=false`, and all code-change, tool-call,
execution, target-interaction, future-state-retest, deployment and attack-path
mutation authority false. Future semantics remain `unresolved` and the
security verdict remains `not_evaluated`.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #284 source or upstream source/tests/docs, later revision-plan
producers/handoffs, snapshot/canonicality owners, scope authorization, provider
behavior, target-capable code, remediation execution or retest execution.
