# Future remediation implementation-plan handoff

This boundary persists and reloads the structured remediation implementation
plan without turning the plan into code or execution authority.

The parser requires the exact plan schema, canonical SHA-256 values, bounded
summary/list/item fields, unique plan-item IDs, constrained change-area values,
non-empty model provenance and all fail-closed authority flags. Both
programmatic tuple-based `as_dict()` values and serialized JSON are accepted
as equivalent representations; duplicate JSON keys are rejected.

After structural validation, the handoff revalidates the exact live
implementation-planning request, accepted remediation review and remediation
proposal. The plan must bind the current implementation-request, review,
proposal and remediation-content digests. Evidence or upstream lineage drift
therefore invalidates a persisted plan before reuse.

A valid handoff still carries only
`implementation_plan_created=true`. Code/config changes, tool calls, target
interaction, remediation execution, future-state retest, deployment and
attack-path mutation remain unauthorized. Future semantics remain
`unresolved` and the security verdict remains `not_evaluated`.
