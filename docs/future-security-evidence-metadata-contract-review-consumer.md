# Persisted evidence metadata-contract review consumer

Persisted metadata-contract reviews must pass both serialization-integrity and
current live-evidence validation. The consumer API
`load_and_validate_future_security_evidence_metadata_contract_review` makes
those checks indivisible for downstream callers.

JSON text is decoded with duplicate-object-key rejection, then passed through
the exact strict #81 handoff parser. The resulting typed review is immediately
revalidated against its freshness admission, upstream evidence-remediation
lineage, candidate RunContext and current StateStore.

A successful return establishes only that the persisted review is canonical and
still matches the live metadata contract. It does not establish evidence
sufficiency and does not select a security classification.

No evidence collection, target interaction, tool execution, remediation,
future-state retest, deployment or attack-path mutation authority is introduced.
