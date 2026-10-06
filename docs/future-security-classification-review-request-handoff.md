# Strict classification-review request handoff

This ST5 boundary parses persisted
`FutureSecurityClassificationReviewRequest` JSON without granting any new
security authority.

The parser requires an exact schema, canonical identifiers, lowercase SHA-256
digests, non-empty sorted/unique candidate evidence and capability IDs, a
supported existing transition-classification claim, and the exact positive
review facts produced by the live request builder.

The following facts must remain true:

- evidence is marked sufficient by the prior operator attestation;
- the existing classification claim is marked justified for later review;
- the sufficiency decision and both review checks have been recorded;
- classification-review eligibility is true;
- classification review is still required.

The following facts must remain false:

- classification selected;
- transition resolution created;
- collection or tool call authorized;
- execution or target interaction allowed;
- remediation authoring or future-state retest allowed;
- deployment authorized;
- attack-path mutation allowed.

`future_semantics` remains `unresolved` and `security_verdict` remains
`not_evaluated`.

The parser recomputes `classification_review_request_sha256` from the
canonical parsed object. Missing/extra fields, noncanonical identities,
unsupported classification claims, forged flags and digest drift fail closed.

Serialization integrity is not live validity. Consumers must still call
`validate_future_security_classification_review_request` against the current
attestation and complete evidence-remediation lineage before follow-up use.
