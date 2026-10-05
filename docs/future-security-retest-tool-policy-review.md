# ST5 retest tool-policy catalog review

This package is the planning-only boundary after an eligible
`FutureSecurityRetestAuthorizationPreflight`. It inspects immutable typed-tool
metadata to show which lab-tool definitions could be considered by a later,
separate planner or execution authorization step.

It does **not** create a `ToolCall`, choose a winning tool, resolve arguments,
invoke a handler, issue an activation permit, select an adapter, or authorize
execution.

## Dependency

Issue #55 / this stacked package depends on issue #53 and its PR #54. It may be
reviewed while stacked on the exact #54 head, but it must not merge before #53
is complete and #54 has been restacked and independently proved after #52.

## Live revalidation

The builder does not trust a serialized preflight in isolation. It rebuilds the
exact authorization preflight from:

- the immutable future-state retest request;
- remediation/retest plan;
- ST4 security-delta report and graph preview;
- transition proposal and resolutions;
- exact run contexts and live `StateStore`;
- authorization grant;
- explicit resolution-to-asset bindings;
- the same explicit authorization check time.

Any stale, tampered, cross-tenant, or lineage-drifted preflight fails closed.
Only `eligible_for_tool_policy_review` may reach catalog review.

## Catalog rules

The supplied `ToolDefinition` tuple is treated as immutable metadata only.
The review:

- rejects duplicate tool IDs;
- rejects malformed tool IDs/capability IDs and duplicate parameter names;
- rejects unknown capabilities;
- considers only capabilities explicitly requested by the retest request;
- surfaces only `LAB_ACTIVE` metadata as candidates;
- rejects analysis, passive-public and `TARGET_ACTIVE` definitions;
- rejects definitions below the active-risk floor;
- rejects `DESTRUCTIVE_LAB_ONLY` definitions;
- rejects definitions above the existing authorization grant's maximum risk;
- records an explicit `no_eligible_lab_tool_metadata` gap when a requested
  capability has no candidate.

A catalog gap is never converted into a security pass or execution approval.

## Deterministic provenance

`tool_catalog_sha256` binds the sorted complete supplied tool catalog,
including tool ID, capability ID, interaction kind, minimum risk, description
and typed parameter metadata.

`review_sha256` additionally binds the exact request/preflight/grant lineage,
authorization maximum risk, per-capability candidates/rejections, gap status
and the non-execution safety flags.

Reordering the supplied definitions does not change the result.

## Fixed safety boundary

Every review hard-codes:

- `tool_policy_review_complete=true`
- `tool_selection_allowed=false`
- `tool_call_created=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

No arguments, credentials, payloads, target network actions, exploit logic,
adapter execution, deployment action, or authorization widening are present in
this package.
