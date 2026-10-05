# ST5 evidence collection request

This package closes the planning gap for ST5 deltas classified as
`insufficient_evidence`. It converts only live-revalidated evidence gaps into
an immutable request stating that **fresh evidence is required**.

It does not collect evidence itself and does not imply that remediation,
retesting, tool selection, target interaction or deployment is permitted.

## Source contract

`build_future_security_evidence_collection_request` consumes the merged
`FutureSecurityRemediationRetestPlan` lineage and rebuilds that plan from the
ST4 report, preview, proposal, verified resolutions, immutable run contexts and
live StateStore before trusting it.

A request exists only when the live plan contains at least one item with all of
these properties:

- classification is `insufficient_evidence`;
- next action is `collect_more_evidence`;
- graph-diff action is `no_graph_change_claim`;
- `evidence_required=true`;
- `remediation_required=false`;
- `future_state_retest_required=false`.

Evidence-complete introduced, worsened, improved and removed outcomes cannot be
converted into this request.

## Provenance, not instructions

Each request item preserves the existing change, subject, resolution, effect,
current-path, evidence and capability identifiers. Existing evidence and
capability IDs are explicitly named `prior_*`: they describe why the current
classification exists; they do not select a future tool or authorize reuse.

The request says only:

- fresh evidence is required;
- a fresh run is required;
- the current evidence gap remains unresolved.

It contains no raw evidence payload, source, metadata, target, tool arguments,
credentials, exploit steps or customer source/config.

## Determinism

Items are canonically sorted by change, subject and resolution identity. The
canonical request SHA-256 binds the full upstream report/plan lineage, every
gap item and all safety flags. Rebuilding from unchanged live state is
deterministic.

## Safety boundary

The request is planning metadata only:

- `collection_authorized=false`
- `capability_selected=false`
- `tool_call_created=false`
- `execution_allowed=false`
- `target_interaction_allowed=false`
- `remediation_authoring_allowed=false`
- `future_state_retest_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

A later package may decide how an explicitly authorized isolated lab run can
collect the missing evidence. That later package must pass its own capability,
scope, authorization and execution-policy gates.

Refs #61.
