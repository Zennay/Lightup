# ST5 remediation evidence bundle

This package is an independent **evidence-remediation** slice on top of the
merged ST5 remediation/retest planner. It prepares a canonical, read-only input
for remediation authoring without modifying customer code/config, invoking a
tool, interacting with a target, or authorizing deployment.

## Why it exists

The remediation/retest plan says which verified security deltas need a
remediation followed by a future-state retest. A remediation role must not trust
that serialized plan by itself or receive unbound free-form context.

`build_future_remediation_evidence_bundle` therefore rebuilds the source plan
from the live ST4 lineage and then re-reads every evidence record referenced by
each remediation-required item.

Only `introduced` and `worsened` items become remediation inputs.
`improved` and `removed` remain verification-only retest work, while
`insufficient_evidence` keeps remediation authoring readiness false.

## Evidence manifest

For every remediation item the bundle retains only bounded provenance:

- evidence ID;
- run ID;
- capability ID;
- evidence kind;
- SHA-256 digest;
- the existing change, subject, resolution, effect, current-path and capability
  lineage.

Raw evidence payloads, raw customer source/config and patches are not copied
into the bundle.

The builder fails closed when referenced evidence is missing, its digest is not
a SHA-256 value, its run is outside the supplied immutable run contexts, or its
capability falls outside the plan item's lineage.

## Determinism

Evidence is sorted by evidence ID and remediation items are canonically sorted
by change/subject/resolution identity. Each item has an
`evidence_manifest_sha256`; the full object has `bundle_sha256` bound to the
source report and remediation-plan digests.

## Safety boundary

This object is authoring input only:

- `execution_allowed=false`
- `code_change_authorized=false`
- `target_interaction_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

A later remediation-authoring component may use this evidence manifest to
propose a fix, but a proposal is not permission to change code/config or
interact with a target. Those remain separate explicitly gated actions.

Refs #59.
