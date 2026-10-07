# ST5 implementation-plan review-request live-validation atomicity

## Scope

This acceptance slice is a tests/docs-only child of the exact branch-only strict implementation-plan review-request handoff recorded by issue #280:

- owner branch: `chatgpt/st5-implementation-plan-review-request-handoff-20261006`
- exact owner head: `08dc953ed7fa9e38976be7d7f66a3ec381ae6124`
- acceptance issue: #485

The owner head is unchanged from its implementation receipt. This slice does not modify #280/#278 production source or existing tests/docs.

## Invariant

`load_and_validate_future_remediation_implementation_plan_review_request` must be a repeatable, read-only persisted-consumer boundary.

For a real canonical implementation-plan review request and live bounded plan lineage:

- repeated strict load + full live validation returns the exact canonical review request;
- caller-owned persisted review-request, implementation-plan, implementation-planning request, remediation review, remediation review-request and remediation proposal dictionaries remain unchanged;
- the corresponding typed implementation-plan/remediation-review/evidence-remediation lineage remains unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease` and `StateStore.add_evidence` are forbidden;
- no verifier, remediation advisor, or other model invocation is introduced by validation.

For deliberate live evidence SHA drift:

- repeated validation fails closed;
- the rejection is deterministic;
- persisted payloads and typed lineage remain unchanged;
- stale live evidence is not repaired or rewritten by validation.

## Authority stop line

Successful validation may preserve only the existing review intent:

- `implementation_plan_review_requested=true`;
- `implementation_plan_accepted=false`;
- `code_change_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No plan acceptance, code/config generation, execution, target action, retest, deployment, verdict, or attack-path mutation is added.

## Collision boundary

Exactly two new files belong to this acceptance slice:

- `tests/test_future_remediation_implementation_plan_review_request_live_validation_atomicity.py`;
- `docs/st5-implementation-plan-review-request-live-validation-atomicity.md`.

Active parallel ownership remains separate:

- #480 owns #278 implementation-plan review-request **builder** input/state atomicity;
- #483 owns #281 implementation-plan **reviewer producer** input/state atomicity;
- issue #280 / its exact branch retains strict persisted review-request handoff source ownership.

## Promotion gate

Keep this child draft until its exact final head has hosted/offline Python 3.11 + 3.14 proof and canonical permanent `vps-bb300bba` proof. Permanent proof must bind the exact head and cover the dedicated atomicity regression, #280 handoff controls, #278 producer controls, compile checks and safety canaries.

Any later absorption belongs to the #280 source owner and must preserve the PLAN-LAB-only stop line.
