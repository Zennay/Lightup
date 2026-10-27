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

The builder fails closed when referenced evidence is missing, its digest is not a canonical lowercase SHA-256 value, its run is outside the supplied immutable run contexts, or its
capability falls outside the plan item's lineage.


## Live revalidation before use

Persisted or transported bundles must be revalidated with
`validate_future_remediation_evidence_bundle` immediately before remediation
authoring consumes them. The validator rebuilds the exact bundle from the live
ST4/ST5 lineage and current evidence ledger, then requires byte-for-byte
dataclass equality with the supplied bundle.

This catches post-build ledger drift even when a changed digest is still a
syntactically valid lowercase SHA-256 value. Capability/run/metadata drift is
rejected earlier by the existing live transition-evidence validation chain.


## Authoring readiness gate

Call `require_future_remediation_evidence_bundle_for_authoring` when the next
step is remediation text authoring. It first performs the complete live bundle
revalidation and then rejects any bundle whose
`remediation_authoring_ready` flag is false.

This is only an input-readiness gate. Passing it does **not** authorize code or
configuration changes, target interaction, deployment, or attack-path mutation.

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
