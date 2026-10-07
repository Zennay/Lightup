# ST5 implementation-plan producer input atomicity

This acceptance slice is a tests/docs-only child of the active bounded
implementation-plan producer in #235.

## Invariant

`generate_future_remediation_implementation_plan` may ask the configured
remediation-advisor model for bounded planning text, but it must not mutate any
caller-owned persisted/live lineage or StateStore state.

The regression proves that:

- two independent gateways returning the same bounded plan yield the exact same
  canonical implementation plan;
- persisted implementation-planning request, review, review request and proposal
  inputs remain unchanged;
- caller-owned authoring/evidence/plan/report/graph/transition/context lineage
  remains unchanged;
- live evidence state remains unchanged;
- the producer never creates a run, acquires a lease or appends evidence;
- successful generation performs exactly one model request per gateway;
- if live evidence drifts before generation, repeated calls reject
  deterministically before any model request and leave stale state plus all
  caller-owned inputs untouched.

## Authority stop line

A successful result may set only `implementation_plan_created=true`.

It must not grant code-change, tool-call, execution, target-interaction,
future-state-retest, deployment or attack-path-mutation authority. Future
semantics remain `unresolved` and the security verdict remains
`not_evaluated`.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #235 source or existing tests/docs, strict implementation-plan handoff,
review/revision ownership, scope authorization, provider implementation,
target-capable code, remediation execution or retest execution.
