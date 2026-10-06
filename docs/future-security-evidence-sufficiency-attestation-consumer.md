# Persisted evidence sufficiency-attestation consumer

The attestation is an already-recorded operator evidence-review result. Loading
it from persistence must not bypass current verifier identity or upstream
evidence validation.

`load_and_validate_future_security_evidence_sufficiency_attestation` rejects
duplicate-key JSON, applies the exact strict #94 attestation parser and then
immediately revalidates the typed attestation against the current verifier,
verifier preflight, sufficiency request, metadata/freshness lineage and
StateStore.

The consumer preserves the recorded disposition and its deterministic derived
flags. It does not turn a justified evidence claim into a LightUp
classification. Classification selection and transition resolution remain
false, as do collection/tool/target execution, remediation, retest, deployment
and attack-path authority.
