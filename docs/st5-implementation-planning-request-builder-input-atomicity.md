# ST5 implementation-planning request builder input atomicity

This acceptance slice is a tests/docs-only child of the active
`FutureRemediationImplementationPlanRequest` producer in #226.

## Invariant

`build_future_remediation_implementation_plan_request` is a pure planning
boundary over already-produced remediation evidence and review lineage.

The regression proves that:

- two successful calls over the same approved live review return the same
  canonical request;
- persisted review, review-request and proposal inputs remain byte-for-byte
  unchanged;
- caller-owned typed authoring/evidence/plan/report/graph/transition/context
  lineage remains unchanged;
- live evidence state remains unchanged;
- the builder does not create runs, acquire leases, append evidence or invoke a
  model;
- if live evidence drifts after the persisted review chain was produced,
  repeated calls reject deterministically and leave both stale state and all
  caller-owned inputs untouched.

## Authority stop line

A successful result may set only
`implementation_planning_requested=true`.

It must keep all later authority false:

- `implementation_plan_created`;
- code-change and tool-call authority;
- execution and target interaction;
- future-state retest;
- deployment;
- attack-path mutation.

Future semantics remain `unresolved` and the security verdict remains
`not_evaluated`.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #226 production source or its existing tests/docs, later
implementation-plan/review/revision branches, scope authorization, gateway
behavior, target-capable code, remediation execution or retest execution.
