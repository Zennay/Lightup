# ST5 implementation-plan review-request strict parser input purity

This acceptance slice is a tests/docs-only child of the strict
implementation-plan review-request handoff in #280.

## Invariant

`future_remediation_implementation_plan_review_request_from_dict` must treat
caller-owned persisted dictionaries as read-only input.

The regression proves that:

- a real canonical producer payload parses repeatedly to the same typed review
  request;
- successful parsing leaves the caller dictionary value-identical to its deep
  snapshot and preserves the exact nested `required_checks` container;
- exact-schema rejection and canonical-shape/digest rejection are deterministic
  across repeated calls;
- rejected dictionaries and their nested `required_checks` container remain
  untouched;
- the parsed artifact remains review-request-only and cannot widen any
  code/tool/execution/target/retest/deploy/attack-path authority.

## Collision boundary

This slice adds one regression module and this document only. It does not
modify #280 parser/validator source or existing tests/docs, #485/#487 live
validation work, review producer/handoff ownership, scope authorization,
provider behavior, target-capable code, remediation execution or retest
execution.

## Safety

Pure in-memory persistence-integrity proof only. It does not touch StateStore,
invoke a model, interact with a target, execute remediation/retests, deploy,
create a security verdict, or mutate attack paths.
