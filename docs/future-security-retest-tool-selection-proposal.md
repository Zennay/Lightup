# ST5 explicit retest tool-selection proposal

This package is the planning-only boundary after a gap-free
`FutureSecurityRetestToolPolicyCatalogReview`.

It records exactly one **explicit proposed LAB_ACTIVE tool ID** for every
capability requested by the isolated future-state retest. It does not create an
executable tool call.

## Dependency

Issue #57 / this stacked package depends on issue #55 and PR #56. It may be
reviewed while stacked on the exact #56 head, but it must not merge before the
#52 -> #54 -> #56 chain has landed and this slice has been restacked and proved
against the resulting `main`.

## Live revalidation

The builder rebuilds the exact catalog review from the same authorization
preflight, retest request, remediation/retest plan, ST4 report, graph preview,
transition proposal, resolutions, run contexts, live `StateStore`,
authorization grant, asset bindings, check time and immutable tool catalog.

A stale, tampered or lineage-drifted review fails closed.

## Proposal rules

A proposal can only be produced when:

- catalog status is `candidate_metadata_available`;
- every requested capability has candidate metadata and no gap;
- exactly one explicit proposal is supplied per requested capability;
- every proposed tool ID is already an admitted candidate for that capability;
- identifiers are normalized and non-empty.

The builder does not auto-pick a candidate. The explicit proposal input is
validated and lineage-bound.

## Deterministic provenance

`proposal_sha256` binds:

- exact request, preflight and catalog-review lineage;
- exact reviewed tool-catalog digest;
- the canonical capability -> proposed-tool mapping;
- every non-execution safety flag.

Proposal ordering is canonical, so reordering equivalent explicit inputs does
not change the result.

## Fixed safety boundary

Every proposal hard-codes:

- `proposal_complete=true`
- `selection_authorized=false`
- `tool_call_created=false`
- `arguments_resolved=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

No target asset, arguments, credentials, payloads, network action, handler
invocation, activation permit, deployment action or authorization widening is
introduced by this package.
