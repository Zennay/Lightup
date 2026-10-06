# Classification-review request live consumer

This boundary is the final **evidence-remediation** ingestion guard before a later,
separate classification-review lane.

It composes two already-established controls:

1. strict persisted handoff parsing from
   `future_security_classification_review_request_handoff`;
2. live rebuilding and lineage validation from
   `future_security_classification_review_request`.

Consumers that use
`load_and_validate_future_security_classification_review_request` therefore
never receive a parsed request unless the exact live evidence-remediation
lineage still matches.

## Fail-closed persisted input

The consumer accepts JSON text or an object. JSON decoding rejects duplicate
object keys instead of silently accepting the last duplicate value. The strict
handoff parser still enforces the exact schema, canonical identifiers and
lowercase SHA-256 values, sorted/unique evidence and capability identities,
fixed safety semantics, and the recomputed request digest.

## Live validation is mandatory

After strict parsing, the consumer immediately invokes
`validate_future_security_classification_review_request`. Any drift in the
attestation, verifier preflight, sufficiency request, metadata review, freshness
admission/constraints, candidate context, evidence ledger, or older ST4/ST5
lineage fails closed.

A successful return means only that the persisted classification-review request
is serialization-valid **and** still matches the current live evidence lineage.

It does **not** select a classification or create a transition resolution. The
following remain false:

- `classification_selected`
- `transition_resolution_created`
- `collection_authorized`
- `tool_call_created`
- `execution_allowed`
- `target_interaction_allowed`
- `remediation_authoring_allowed`
- `future_state_retest_allowed`
- `deployment_authorized`
- `attack_path_mutation_allowed`

`future_semantics` remains `unresolved` and `security_verdict` remains
`not_evaluated`.

Classification review itself is deliberately out of scope for this package.
