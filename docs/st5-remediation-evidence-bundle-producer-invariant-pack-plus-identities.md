# ST5 remediation evidence-bundle producer-invariant pack + canonical identities

This forward composition is a collision-safe child of the already proven
`chatgpt/st5-remediation-evidence-bundle-producer-invariants-pack-20261006`
head `8e4a0d2a8bfd9c1a771c44c12d5d5fe975b31da2`.

It does not modify that owner's branch or PR #194 source. It adds only the #405
canonical-identity acceptance contract and this absorption map.

## Included persisted-boundary contracts

The parent pack already carries:

- #398 — positive exact twin versions;
- #399 — exact nested evidence capability coverage;
- #400 — INTRODUCED/WORSENED current-path semantics;
- #401 — canonical resolution ID and effect lineage;
- #402 — exact `future-transition-verification` evidence kind.

This child adds:

- #405 — producer-canonical `change_node_id`, `subject_node_id`, nested
  `evidence_id`, and nested `run_id`.

The #405 forged cases recompute all affected public digests, so stale-digest
rejection cannot satisfy the contract.

## Narrow source-owner absorption map

Keep the existing strict schema, digest recomputation, safety flags, readiness
checks and immediate live-lineage validator. Add only locally derivable producer
invariants before constructing the persisted typed bundle:

1. validate `current_twin_version` and `twin_version` as positive exact ints;
2. require evidence capability set == enclosing item capability set;
3. require INTRODUCED to have no current path and WORSENED to retain current
   path lineage;
4. require `resolution_id` to match
   `transition-resolution:<24 lowercase hex>`;
5. require effect lineage non-empty, canonical, sorted and unique;
6. require evidence `kind` exactly `future-transition-verification`;
7. require `change_node_id`, `subject_node_id`, `evidence_id`, and
   `run_id` to use the upstream canonical identifier shape: exact string,
   non-empty, already trimmed, at most 256 characters, and free of ASCII
   controls/DEL.

Reject persisted input rather than normalizing it. Live StateStore freshness and
complete lineage equality remain the responsibility of the existing immediate
live validator.

## Proof status

The parent #398–#402 pack is independently permanent-VPS proven on
`vps-bb300bba`. #405 is independently hosted expected-RED proven on Python
3.11 and 3.14 at exact head
`edb83f2e1cd119b05406c17011c12fa34c5d4d9a`. Its permanent-VPS proof is also green:
zCloud run `37547085717` succeeded on `vps-bb300bba` for Python 3.11 and 3.14,
with the parent #194 handoff green, exactly 12 #405 expected-RED failures per
interpreter, canonical producer control green, safety canaries green, and zero
production-source changes. Receipt artifact `11451530786` has digest
`sha256:f2fadd6f233c327652d0ccb25dfdf54e6dec4630d87a5c520b223ef0913e146c`;
validation-only zCloud PR #793 is closed unmerged.

This forward composition may now be proven as one combined acceptance head, but
must not be promoted as a source fix. The #194 source owner still needs to absorb
the full invariant set and produce an exact updated-head green proof.

## Safety

Parser-integrity acceptance only. No evidence collection, model invocation,
target interaction, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
