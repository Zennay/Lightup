# Persisted evidence sufficiency verifier-preflight consumer

Verifier preflight proves only that a current operator identity is eligible to
perform the independent sufficiency review. It is not a review result.

`load_and_validate_future_security_evidence_sufficiency_verifier_preflight`
rejects duplicate-key JSON, applies the exact strict #91 handoff parser and
immediately revalidates the preflight against the current verifier identity,
sufficiency-review request, metadata/freshness lineage and StateStore.

A successful return preserves `eligible_for_sufficiency_review=true` while
`sufficiency_decision_created=false`, sufficiency remains unevaluated, no
classification or transition resolution is selected, and all execution,
target, remediation, retest, deployment and attack-path authority remains
false.
