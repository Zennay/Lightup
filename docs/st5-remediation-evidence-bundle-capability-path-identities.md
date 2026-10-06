# ST5 remediation evidence-bundle capability/path identifier acceptance

Issue: #407

This acceptance slice is a tests/docs-only child of exact active remediation evidence-bundle handoff PR #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`.

## Gap

The persisted #194 parser currently accepts `capability_ids` and `current_attack_path_ids` through a generic unique non-empty string-list parser. That is weaker than the already-live-validated ST4 transition-resolution contract.

ST4 `_canonical_tuple` applies `_require_identifier` to both collections. The producer-reachable shape is therefore:

- every identifier is a string and non-empty;
- no leading or trailing whitespace;
- at most 256 characters;
- no ASCII control characters or DEL;
- collection members are unique;
- the collection is canonically sorted;
- `capability_ids` is non-empty;
- `current_attack_path_ids` follows the existing classification-dependent empty/non-empty semantics.

PR #60 copies those already validated collections into the remediation evidence bundle. A persisted caller should not be able to reconstruct shapes that the live producer cannot emit merely by recomputing public digests.

## Acceptance contract

The regression module proves:

1. a real WORSENED producer bundle remains a green round-trip control;
2. item and nested-evidence capability identifiers reject padded, control-character-bearing and >256-character text while preserving matching capability sets and recomputed manifest/bundle digests;
3. current-path identifiers reject the same non-canonical shapes with a recomputed bundle digest;
4. capability collections reject non-canonical ordering even when the item/evidence capability sets still match and all affected public digests are recomputed;
5. current-path collections reject non-canonical ordering with a recomputed bundle digest.

The RED cases call the strict parser directly, not the live validator, so a later live-lineage mismatch cannot accidentally satisfy the contract.

## Non-overlap

This is intentionally distinct from:

- #399: exact evidence capability set == item capability set;
- #400: INTRODUCED/WORSENED current-path presence semantics;
- #401: canonical resolution/effect lineage;
- #402: exact evidence kind;
- #405/#406: change/subject/evidence/run canonical identifiers;
- #404: direct typed-object constructor invariants.

No #194 or #60 production source, existing tests/docs, scope authorization, target adapter, remediation/retest execution, deployment, verdict or attack-path mutation code is modified.

## Expected state

Before the #194 owner absorbs the narrow parser checks, the canonical producer control should pass and the forged canonical-shape/order cases should fail the acceptance assertions (expected RED).

Promotion requires those RED cases to become green without weakening the existing #194 strict handoff, #60 live validation, #399/#400/#401/#402/#405 contracts, or safety stop lines.

## Safety

Persistence-integrity proof only. No evidence collection, model invocation, target interaction, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
