# Future security classification-review request

This ST5 package is a bounded handoff from evidence remediation into a later
classification-review stage.

It accepts only a **live-valid** `FutureSecurityEvidenceSufficiencyAttestation`
whose disposition is `sufficient_claim_justified`. The producer revalidates
that attestation against the verifier preflight, sufficiency request,
metadata-contract review, freshness admission and the complete upstream
evidence-remediation lineage before creating anything.

A successful request means only:

- the operator attested that the candidate evidence is sufficient;
- the existing candidate classification **claim** is justified enough to be
  reviewed;
- a later classification review is required.

It does **not** mean that LightUp has selected or accepted the classification.

The request keeps these boundaries fail-closed:

- `classification_selected=false`;
- `transition_resolution_created=false`;
- `collection_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `remediation_authoring_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

The export carries only bounded identity and digest lineage. It does not copy
raw evidence metadata, source, payload, target, arguments, credentials,
passwords, or session material.

Persisted requests must be passed through
`validate_future_security_classification_review_request` before follow-up
use. Validation rebuilds the request from the live attestation and upstream
lineage, so attestation drift or forged authority flags fail closed.

This package is planning/handoff only. It performs no target interaction,
classification decision, remediation authoring, retest, deployment, or
attack-path mutation.
