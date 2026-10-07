# ST5 implementation-plan review live-validation atomicity

## Scope

This acceptance slice is a tests/docs-only child of the exact branch-only strict implementation-plan review handoff recorded by issue #283:

- owner branch: `chatgpt/st5-implementation-plan-review-handoff-20261006`
- exact owner head: `996fa91daac86136caf2dc0c900c2edd84a0703b`
- acceptance issue: #490

The #283 branch remains at its recorded exact head. This slice does not modify #283/#281 production source, existing handoff tests, or reviewer behavior.

## Invariant

`load_and_validate_future_remediation_implementation_plan_review` must be a repeatable, read-only persisted-consumer boundary.

For a canonical independent implementation-plan review and live strict planning lineage:

- repeated strict load + full live validation returns the exact canonical review;
- caller-owned persisted review, plan review-request, implementation plan, implementation-planning request, remediation review, remediation review-request and proposal dictionaries remain unchanged;
- corresponding typed planning/review/evidence-remediation lineage remains unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease` and `StateStore.add_evidence` are forbidden;
- validation does not re-invoke the verifier or remediation advisor.

For deliberate live evidence SHA drift:

- repeated validation fails closed;
- the rejection is deterministic;
- persisted payloads and typed lineage remain unchanged;
- stale live evidence is not repaired or rewritten.

## Authority stop line

An approved persisted review may preserve reviewed-planning-text acceptance only:

- `implementation_plan_review_completed=true`;
- `implementation_plan_accepted=true`;
- `code_change_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No code/config generation, target action, tool execution, retest, deployment, security verdict, or attack-path mutation is added.

## Collision boundary

Exactly two new files belong to this slice:

- `tests/test_future_remediation_implementation_plan_review_live_validation_atomicity.py`;
- `docs/st5-implementation-plan-review-live-validation-atomicity.md`.

Parallel ownership remains separate:

- #483 owns #281 reviewer producer input/state atomicity;
- #327 owns reviewer provenance source hardening;
- #488 owns #280 strict parser purity;
- #487 owns #280 review-request live-validation atomicity;
- issue #283 and its exact branch retain persisted review handoff source ownership.

## Promotion gate

Keep this child draft until its exact final head has hosted/offline Python 3.11 + 3.14 proof and canonical permanent `vps-bb300bba` proof. Permanent proof must bind the exact child head and cover the dedicated atomicity regression, #283 handoff controls, #281 producer controls, compile checks and safety canaries.

Any absorption belongs to the #283 owner and must preserve the PLAN-LAB-only authority boundary.
