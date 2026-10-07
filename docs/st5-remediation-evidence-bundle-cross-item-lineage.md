# ST5 remediation evidence-bundle cross-item lineage acceptance

This tests/docs-only acceptance contract sits directly above exact active #194
remediation evidence-bundle handoff head
`ec4b09f539289fbf3b497a534980323bd3c11bef`.

## Gap

The strict persisted parser currently tracks item uniqueness only as the complete
triple:

`(change_node_id, subject_node_id, resolution_id)`.

That allows two otherwise-distinct persisted bundle items to reuse one
`change_node_id`, reuse one `resolution_id`, or let different changes claim
the same current attack-path identity, provided the full triples still differ.

That state is not producer-reachable. The #60 remediation evidence bundle is
built only from the live-valid remediation/retest plan, and the upstream
ST4/ST5 lineage already enforces the independent cross-item ownership
invariants proven by #378.

Because `bundle_sha256` is public and deterministic, a persisted caller can
forge one of these collisions and recompute a matching digest. Digest integrity
alone therefore does not preserve producer-reachable cross-item lineage at the
#194 parser boundary.

## Acceptance

The regression contract requires:

1. an untouched real WORSENED producer bundle still round-trips;
2. two distinct persisted items cannot reuse one `change_node_id`;
3. two distinct persisted items cannot reuse one `resolution_id`;
4. different changes cannot claim the same `current_attack_path_id`;
5. every forged payload keeps a canonical item ordering, uses otherwise
   structurally valid item data, and recomputes a matching `bundle_sha256`;
6. persisted input is rejected rather than normalized or silently
   deduplicated.

The cloned second item receives a distinct subject, distinct evidence identity,
and—except for the invariant deliberately under test—distinct resolution/path
lineage. This keeps each RED case narrow.

## Non-overlap

Issue #429 adds only this regression module and this contract document. It does
not modify #194 source/tests/docs and does not take source ownership.

It is distinct from:

- #398 positive twin versions;
- #399 exact evidence/capability coverage;
- #400 classification/current-path presence semantics;
- #401 canonical resolution/effect lineage;
- #402 canonical evidence kind;
- #405/#406 item/evidence identifier shape;
- #407/#408 capability/path identifier shape and ordering;
- #423/#424 top-level lineage identity shape;
- #319 snapshot isolation.

No evidence collection, model invocation, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.

## Expected state

Until #194's source owner absorbs this narrow invariant, the canonical producer
control should stay green while the three forged cross-item cases are expected
RED. After absorption, the target is 3 RED -> 0 RED while the parent handoff,
real producer integration and safety canaries remain green.
