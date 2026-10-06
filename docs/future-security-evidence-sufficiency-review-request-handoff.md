# ST5 evidence sufficiency-review request serialized handoff

This boundary protects persisted
`FutureSecurityEvidenceSufficiencyReviewRequest` JSON from acquiring stronger
meaning through transport or storage tampering.

Use `future_security_evidence_sufficiency_review_request_from_dict` for
deserialization. It requires the exact schema, strict primitive types,
canonical identifiers and lowercase SHA-256 values, sorted/unique candidate
evidence and capability IDs, and the exact canonical independent review
checks.

The candidate classification is still an **evidence claim**, not a LightUp
classification decision. The parser requires both review obligations to remain
active:

- `independent_verifier_required=true`;
- `review_required=true`.

It also requires `metadata_contract_verified=true` and
`freshness_check_passed=true`, while evidence sufficiency, classification and
transition resolution remain unevaluated/unselected/uncreated. Every
collection, tool, target, execution, remediation, retest, deployment and
AttackPath authority flag stays false.

The parser recomputes `sufficiency_request_sha256` from canonical parsed
content. A matching digest proves serialization integrity only. Downstream code
must still call
`validate_future_security_evidence_sufficiency_review_request` against the
live metadata review, admission, constraints, full ST4/ST5 lineage, candidate
RunContext and current StateStore.

This layer performs no evidence collection, target interaction, security
outcome selection, execution, remediation authoring, retest execution,
deployment or AttackPath mutation.

Refs #84.
