# ST5 evidence metadata-contract review serialized handoff

This handoff protects persisted
`FutureSecurityEvidenceMetadataContractReview` JSON from being promoted into
stronger semantics by storage or transport tampering.

Use `future_security_evidence_metadata_contract_review_from_dict` for
deserialization. The parser requires the exact schema, strict primitive types,
canonical identifiers, canonical lowercase SHA-256 values and non-empty
sorted/unique candidate evidence and capability identity lists.

The candidate classification remains an **evidence claim** represented by the
existing `AttackPathTransitionClassification` enum. Parsing that claim does
not select or accept a LightUp security classification.

The handoff requires `metadata_contract_verified=true`,
`freshness_check_passed=true`, `evidence_sufficiency_evaluated=false`,
`classification_selected=false`, `transition_resolution_created=false`,
all authority flags false, `future_semantics=unresolved` and
`security_verdict=not_evaluated`. The parser recomputes `review_sha256`
from the canonical parsed content.

A successfully parsed object proves **serialization integrity only**. Before
downstream use, callers must still invoke
`validate_future_security_evidence_metadata_contract_review` against the live
admission, constraints, request, ST4/ST5 lineage, candidate RunContext and
current StateStore. Live validation detects evidence-ledger or lineage drift.

This layer performs no evidence collection, target interaction, tool
selection, execution, remediation authoring, retest execution, deployment or
AttackPath mutation.

Refs #79.
