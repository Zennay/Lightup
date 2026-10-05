# ST5 retest authorization preflight

This package binds an immutable isolated future-state retest request to an
existing authorization grant before any tool, adapter, risk level, credential,
or network action may be considered.

## Boundary

The output is planning metadata only:

- `execution_allowed=false`
- `target_interaction_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`
- `tool_policy_review_required=true`

A successful preflight means only
`eligible_for_tool_policy_review`. It does not authorize execution.

## Live revalidation

The builder independently reconstructs the exact
`FutureSecurityRetestRequest` from its upstream remediation plan, ST4 report,
preview, proposal, resolutions, run contexts, and live `StateStore`. A stale,
tampered, cross-tenant, or lineage-drifted request is rejected.

Each retest item must have exactly one explicit asset binding keyed by its
`resolution_id`. Wildcard bindings are rejected. This avoids ambiguous
one-to-many bindings when a single change node produces multiple resolved
retest items.

## Authorization decision

The preflight requires the authorization grant to:

- belong to the same client and source engagement;
- be current at an explicit timezone-aware check time;
- permit recurring retests;
- contain every explicitly bound asset;
- allow every requested capability.

Expired, non-recurring, asset-out-of-scope, or capability-incomplete grants
produce `reauthorization_required` rather than an executable request.

The deterministic preflight digest binds the request SHA, grant identity,
hashed authorization reference, exact check time, ordered item bindings,
requested capabilities, status, and reasons.

This is the stacked planning package for issue #53. It must remain draft until
issue #48 / PR #52 has merged and this branch is restacked onto the resulting
`main`.
