# ST5 implementation-planning request strict parser input purity

This acceptance slice is a tests/docs-only child of the strict
implementation-planning request handoff in #230.

## Invariant

`future_remediation_implementation_plan_request_from_dict` must treat
caller-owned persisted dictionaries as immutable input.

The regression proves that:

- a real canonical producer payload parses repeatedly to the same typed
  implementation-planning request;
- successful parsing leaves the caller dictionary value-identical to its deep
  snapshot;
- exact-schema and canonical-shape/digest rejections are deterministic on
  repeated calls and leave the rejected dictionary unchanged;
- the parsed artifact remains planning-request-only and cannot widen
  implementation-plan lifecycle or any code/tool/execution/target/retest/
  deploy/attack-path authority.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #230 parser/validator source or existing tests/docs, #478/#482 live
validation work, implementation-plan producer/handoff ownership, scope
authorization, provider behavior, target-capable code, remediation execution
or retest execution.

## Safety

Pure in-memory persisted-input integrity proof only. It does not touch
StateStore, invoke a model, interact with a target, execute remediation/retests,
deploy, create a security verdict, or mutate attack paths.
