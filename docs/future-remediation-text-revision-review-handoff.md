# Strict revised-remediation review handoff

This boundary persists and reloads the independent verifier result for revised
remediation prose while preserving the distinction between accepted prose and
authorized action.

The handoff requires the exact review schema, canonical SHA-256 values,
non-empty reviewer provenance, the fixed review checks in canonical order,
valid check results, decision/check coherence, a bounded summary and the exact
review digest. Serialized JSON rejects duplicate keys before normal decoding.

A structurally valid persisted review is not enough. Before reuse the handoff
also validates the strict revised review request and revised proposal, which
transitively revalidate the revision request, prior review, original proposal
and live evidence ledger.

An approved review may retain remediation_accepted=true, meaning only that the
revised **text** passed the independent review contract. It still cannot
authorize code/config generation, tool calls, target interaction, remediation
execution, future-state retest, deployment, future-state resolution,
attack-path mutation or a security verdict.
