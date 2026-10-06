# Future remediation text review-request handoff

This contract persists and reloads the independent remediation-text review
request without turning review intent into remediation acceptance or action
authority.

The parser requires the exact schema, canonical SHA-256 values, strict primitive
types, the fixed four-check review rubric, duplicate-key rejection and all
fail-closed authority flags. The review-request digest is recomputed from the
canonical fields.

After structural parsing, the request is rebuilt from the strict live
remediation-text proposal path. Any drift in the evidence ledger, authoring
request, proposal lineage, model content digest, provider/model provenance or
review-request fields therefore invalidates the persisted request before reuse.

A valid handoff still means only `review_requested=true`.
`remediation_accepted` remains false, and code changes, tool calls, target
interaction, remediation execution, future-state retest, deployment and
attack-path mutation remain unauthorized. Future semantics stay unresolved and
the security verdict stays `not_evaluated`.
