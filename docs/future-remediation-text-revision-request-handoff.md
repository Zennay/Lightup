# Future remediation text revision-request handoff

This boundary persists and reloads the planning-only request produced when an
independent remediation-text review requires revision.

## Strict integrity

The handoff requires the exact schema, canonical lowercase SHA-256 values, the
fixed review decision revision_required, at least one unique known review check
in canonical rubric order, and the exact deterministic revision-request digest.
Serialized JSON rejects duplicate keys before normal decoding.

revision_requested must remain true. remediation_accepted and every code, tool,
execution, target, retest, deployment and attack-path authority flag must remain
false. Future semantics stay unresolved and the security verdict stays
not_evaluated.

## Live lineage

A structurally valid persisted request is not enough. The handoff rebuilds the
revision request from the strict persisted review handoff and compares the
result exactly. That composes the live checks for the review request, proposal
and evidence ledger without re-invoking a model.

Evidence drift, review substitution, proposal drift or request drift therefore
invalidates the persisted revision request before any later consumer can use it.

## Stop line

This artifact authorizes only another pass over remediation prose. It does not
authorize generation or application of code/config changes, tool calls, target
interaction, remediation execution, future-state retest, deployment,
attack-path mutation or a security verdict.
