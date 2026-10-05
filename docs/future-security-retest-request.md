# ST5 isolated future-state retest request

This package converts a live-revalidated `FutureSecurityRemediationRetestPlan`
into immutable planning metadata for a later isolated future-state retest.

## Safety boundary

The request is deliberately non-executable:

- `isolated_future_state_required=true`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

Creating the request does not authorize a tool call. A later execution lane must
still pass the existing authorization, scope, risk, capability, and tool-policy
gates.

## Fail-closed lineage

The builder independently reconstructs the remediation/retest plan from the
live ST4 report inputs and `StateStore`. Serialized or stale planning data is
not trusted.

The request keeps exact client, current-twin, future-twin, ChangeSet, proposal,
impact-analysis, preview, report, remediation-plan, resolution, effect,
evidence, capability, and current attack-path lineage.

Any plan containing an insufficient-evidence item is rejected. Such an item
must first collect evidence and produce a newly revalidated plan.

## Retest semantics

- `introduced` / `worsened` become `remediation_validation` requests.
- `improved` / `removed` become `improvement_verification` requests.
- only plan items with `future_state_retest_required=true` are included.
- the request digest is deterministic, so replay of identical evidence and
  lineage produces the same request.

This is the planning handoff required by issue #48. It intentionally does not
start a lab, network request, remediation, merge, or deployment.
