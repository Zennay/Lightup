# Revised remediation-text review-request handoff

This boundary persists and reloads the independent-review request for revised
remediation prose while keeping the request strictly planning-only.

## Strict integrity

The handoff requires the exact schema, canonical lowercase SHA-256 values,
non-empty provider/model provenance and the fixed four-check review rubric in
canonical order. Serialized JSON rejects duplicate keys before normal decoding.

The review-request digest is recomputed from the revised-proposal,
revision-request, prior-review and revised-content lineage plus model provenance
and the fixed authority state.

review_requested must remain true. remediation_accepted and every code, tool,
execution, target, retest, deployment and attack-path authority flag must remain
false. Future semantics remain unresolved and the security verdict remains
not_evaluated.

## Live lineage

A structurally valid persisted request is not enough. The handoff rebuilds the
request from the strict live revised-proposal handoff and requires exact
equality. That transitively revalidates the revision request, prior review,
original proposal and current evidence lineage without invoking a model.

Evidence drift, revised-proposal substitution, review drift or request drift
therefore invalidates persisted review-request reuse.

## Stop line

This artifact requests another independent review only. It does not accept
remediation prose or authorize code/config generation, tool calls, target
interaction, remediation execution, future-state retest, deployment,
attack-path mutation or a security verdict.
