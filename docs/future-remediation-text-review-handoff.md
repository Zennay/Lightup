# Future remediation text review handoff

This boundary persists and reloads the independent remediation-text verifier
result while preserving the distinction between **accepted prose** and
**authorized action**.

## Strict review integrity

The handoff requires the exact review schema, canonical SHA-256 values,
non-empty reviewer provenance, the four fixed review checks in canonical order,
valid check results, decision/check coherence, a bounded summary and the exact
review digest.

Both programmatic `as_dict()` values and serialized JSON are accepted as
equivalent representations; JSON still rejects duplicate keys before normal
decoding.

## Live lineage

A structurally valid persisted review is not enough. Before reuse the handoff
also requires the referenced review request and remediation proposal to pass
their strict live validators. The review must bind the exact current:

- review-request SHA-256;
- remediation proposal SHA-256;
- remediation content SHA-256.

Evidence-ledger or upstream lineage drift therefore invalidates a previously
persisted review without re-invoking the verifier model.

## Authority stop line

An approved review may retain `remediation_accepted=true`, meaning only that
the remediation **text** passed the review contract. It still cannot authorize
code/config changes, tool calls, target interaction, remediation execution,
future-state retest, deployment or attack-path mutation. Future semantics remain
`unresolved` and the security verdict remains `not_evaluated`.
