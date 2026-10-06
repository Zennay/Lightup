# Persisted evidence sufficiency-review request consumer

The sufficiency-review request remains a bounded instruction to perform an
independent review. It is not itself a sufficiency result or classification
decision.

`load_and_validate_future_security_evidence_sufficiency_review_request`
rejects duplicate-key JSON, applies the exact strict #86 handoff parser and then
immediately revalidates the typed request against the live metadata review,
freshness admission, upstream ST5 lineage, candidate RunContext and StateStore.

A successful return means only that the persisted review obligation remains
canonical and current. Evidence sufficiency is still unevaluated, no
classification or transition resolution is selected, and all execution,
target, remediation, retest, deployment and attack-path authority remains
false.
