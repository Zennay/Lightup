# ST5 remediation authoring request — canonical persisted identities

Issue #421 isolates canonical identity preservation at the strict persisted #198
authoring-request boundary.

## Contract

The live producer chain supplies canonical ST4/ST5 lineage identifiers.
Persisted requests must not accept identity text that the producer cannot emit.

The following fields must remain exact non-empty canonical identifiers:

- item `change_node_id`;
- item `subject_node_id`;
- nested evidence `evidence_id`;
- nested evidence `run_id`.

Canonical means already trimmed, no ASCII control characters or DEL, and at
most 256 characters. Input is rejected rather than normalized.

Every forged item identity recomputes `request_sha256`. Every forged evidence
identity recomputes both `evidence_manifest_sha256` and `request_sha256`, so
stale-digest rejection cannot satisfy this contract.

## Expected pre-fix result

Twelve subcases are intentionally RED on current #198: padded,
control-character and over-256-character values across all four identity fields.
The canonical WORSENED producer request remains the green control.

## Collision and safety boundary

Tests/documentation only. No #198/#196/#60 source or existing tests are changed.
This is separate from #410 capability/path canonicalization, #412 evidence kind,
#414 capability coverage, #416 positive versions, #418 path semantics, and #420
resolution/effect lineage.

No model invocation, target interaction, code/config generation, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
