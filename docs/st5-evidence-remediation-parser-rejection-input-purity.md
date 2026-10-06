# ST5 rejected evidence-remediation parser input purity

Issue #329 extends the successful-input purity contract from #323/#324 to rejected persisted payloads without modifying that sibling.

## Contract

A strict evidence-remediation parser may reject malformed or tampered caller-owned input, but rejection must itself be side-effect-free. The parser must not sort, pop, normalize, replace, rewrite, or otherwise mutate any caller-owned dictionary/list while reaching the failure.

The proof is based on exact PR #98 head `1369e04a33d55a91479d434208cc6064ac55809d` and covers the five real persisted boundaries present in that ancestry:

- evidence collection request;
- freshness constraints;
- freshness admission;
- evidence-sufficiency attestation;
- classification-review request.

For every real producer artifact two rejection paths are exercised:

1. an exact-schema violation through an unknown top-level field;
2. an otherwise canonical-shape payload with only its canonical artifact digest replaced by a different lowercase SHA-256.

For each deliberately tampered JSON-decoded object the regression snapshots, **after tampering and before parsing**:

- the complete nested value graph;
- JSON key/list ordering;
- every nested dictionary/list object identity.

The exact same caller-owned object is then rejected twice. Both attempts must raise the same error message and leave content, ordering, nested container identities and planning-only authority fields unchanged.

## Security stop line

Failure cannot manufacture classification selection, transition resolution, collection/tool/target/execution authority, remediation/retest authority, deployment authority or attack-path mutation. Where present, future semantics remain `unresolved` and the security verdict remains `not_evaluated`.

## Safety and collision boundary

This package adds one regression module and this document only. It does not modify #323/#324, any producer/parser/consumer implementation, existing handoff tests, snapshot siblings, #325/#326, implementation-plan reviewer provenance work, scope authorization, or target-capable code.

All proof is in-memory. No evidence collection, model invocation, target interaction, tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
