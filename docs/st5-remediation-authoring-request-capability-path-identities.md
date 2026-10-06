# ST5 remediation authoring-request capability/path identifier acceptance

Issue: #409

This acceptance slice is a tests/docs-only child of exact active remediation-authoring request handoff PR #198 head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Gap

The persisted #198 parser currently accepts `capability_ids` and `current_attack_path_ids` through a generic unique non-empty string-list parser. That is weaker than the producer-reachable lineage copied by #196 from the live-valid remediation evidence bundle.

The upstream ST4 transition-resolution contract already guarantees for both collections:

- every identifier is a string and non-empty;
- no leading or trailing whitespace;
- at most 256 characters;
- no ASCII control characters or DEL;
- collection members are unique;
- the collection is canonically sorted;
- `capability_ids` is non-empty;
- `current_attack_path_ids` retains classification-dependent presence semantics.

The authoring-request producer copies those tuple values unchanged. Persisted input should not be able to reconstruct shapes the live producer cannot emit merely by recomputing public digests.

## Acceptance contract

The regression module proves:

1. a real WORSENED producer request remains a green round-trip control;
2. item and nested-evidence capability identifiers reject padded, control-character-bearing and >256-character text while preserving matching capability sets and recomputed manifest/request digests;
3. current-path identifiers reject the same non-canonical shapes with a recomputed request digest;
4. capability collections reject non-canonical ordering even when item/evidence capability sets still match and all affected public digests are recomputed;
5. current-path collections reject non-canonical ordering with a recomputed request digest.

The RED cases call the strict #198 parser directly, not the live validator, so a later live-lineage mismatch cannot accidentally satisfy the contract.

## Non-overlap

This is downstream-only and intentionally distinct from:

- #407/#408: analogous canonical capability/path acceptance at the earlier #194 bundle handoff;
- #198 source ownership;
- #196 producer ownership;
- #255 direct in-process authoring-item construction hardening.

Exactly one new regression module and one new document are added. No production source, existing tests/docs, scope authorization, model gateway, target adapter, remediation/retest execution, deployment, verdict or attack-path mutation code is modified.

## Expected state

Before the #198 owner absorbs the narrow parser checks, the canonical producer control should pass and the forged canonical-shape/order cases should fail the acceptance assertions (expected RED).

Promotion requires those RED cases to become green without weakening live validation or the fail-closed authority stop lines.

## Safety

Persistence-integrity proof only. No model invocation, code/config generation, target interaction, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
