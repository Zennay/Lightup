# Scope authorization: interaction-kind fail-closed acceptance

## Boundary
`ExecutionPolicy.decide()` must not treat arbitrary `ExecutionRequest.interaction` values as `TARGET_ACTIVE` just because earlier enum identity branches do not match. The currently implemented final fallthrough path checks the valid grant and can return an allow decision for an unknown string, null, number, or arbitrary object.

## Acceptance
The standalone offline test `tests/test_scope_interaction_kind_failclosed_acceptance.py` builds one valid in-memory grant and confirms canonical `InteractionKind.TARGET_ACTIVE` still permits its exact authorized asset/capability/risk. It then requires every non-enum interaction shape to be denied even under the same valid grant. This is **expected RED** until the execution-policy source owner adds explicit `TARGET_ACTIVE` identity validation before the active-grant branch.

## Ownership and safety
Tests/docs only; no production source is changed. Do not modify the actively owned execution-policy surface in PR #100 or its descendants. No DNS, HTTP, target interaction, scanning, active capability dispatch, remediation, deployment, or authority widening. This test does not activate any target execution.
