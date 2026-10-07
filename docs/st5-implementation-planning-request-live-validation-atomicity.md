# ST5 implementation-planning request live-validation atomicity

## Scope

This acceptance slice is a tests/docs-only child of the exact active implementation-planning request handoff owner:

- owner PR: #230
- owner branch: `chatgpt/st5-remediation-implementation-plan-request-handoff-20261006`
- exact owner head: `365774588d5d340d4c2ed41e78478e62e1fcf455`
- acceptance issue: #478

It does not modify the handoff implementation, the implementation-planning request producer, or any downstream implementation-plan/review/revision source.

## Invariant

`load_and_validate_future_remediation_implementation_plan_request` must be a repeatable, read-only persisted-consumer boundary.

For a real approved remediation-review lineage and canonical persisted implementation-planning request:

- repeated validation returns the exact same canonical typed request;
- caller-owned persisted implementation request, remediation review, review request and proposal dictionaries remain unchanged;
- caller-owned typed implementation request plus review/proposal/request/bundle/plan/report/preview/transition/resolution/context lineage remains unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease` and `StateStore.add_evidence` are forbidden during validation;
- no model request is required or introduced by this acceptance slice.

For deliberate live evidence SHA drift:

- repeated validation fails closed;
- the rejection is deterministic;
- persisted input is not normalized or mutated;
- typed lineage remains unchanged;
- the stale evidence row is not repaired, rewritten or otherwise mutated by validation.

## Authority stop line

A valid handoff may preserve only the already-owned planning intent:

- `implementation_planning_requested=true`;
- `implementation_plan_created=false`;
- `code_change_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

This proof does not create implementation plans, patches, commands, tool calls, target arguments, retests, deployments, verdicts, or attack-path mutations.

## Collision boundary

Exactly two new acceptance files belong to this slice:

- `tests/test_future_remediation_implementation_plan_request_live_validation_atomicity.py`;
- `docs/st5-implementation-planning-request-live-validation-atomicity.md`.

No existing source, tests or documentation are edited.

Active parallel work remains separate:

- #473 owns implementation-planning request **builder** input/state atomicity above #226;
- #476 owns implementation-plan **producer/model-call** input/state atomicity above #235;
- #230 retains all production/source ownership for strict persisted implementation-planning request handoff semantics.

## Promotion gate

Keep the acceptance child draft until its exact final head has:

1. hosted/offline Python 3.11 and 3.14 proof;
2. canonical permanent `vps-bb300bba` proof;
3. exact-head receipt binding the dedicated atomicity regression, parent handoff/producer controls, compile checks and safety canaries.

Absorption, if desired, belongs to the #230 source owner and must preserve the PLAN-LAB-only authority boundary.
