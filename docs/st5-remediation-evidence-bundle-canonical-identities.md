# ST5 remediation evidence-bundle canonical identity acceptance

This is a tests/docs-only acceptance contract above the exact active #194
remediation-evidence-bundle handoff head
`ec4b09f539289fbf3b497a534980323bd3c11bef`.

## Gap

The strict persisted parser currently uses a generic non-empty-string check for
several identities copied from the already validated ST4 transition resolution.
That is weaker than the producer contract. ST4 accepts canonical identifiers
only: values are non-empty, already trimmed, contain no ASCII control characters
or DEL, and are at most 256 characters.

The locally derivable invariant applies here to:

- remediation item `change_node_id`;
- remediation item `subject_node_id`;
- nested evidence `evidence_id`;
- nested evidence `run_id`.

A persisted caller can currently replace one of these values with
whitespace-padded, control-character-bearing, or overlong text and recompute the
public evidence-manifest and bundle digests. Digest integrity therefore does not
by itself preserve the producer-reachable identity shape.

## Acceptance

The regression contract requires:

1. an untouched real WORSENED producer bundle still round-trips;
2. non-canonical item identity text fails closed after recomputing a matching
   `bundle_sha256`;
3. non-canonical evidence identity text fails closed after recomputing both the
   matching `evidence_manifest_sha256` and `bundle_sha256`;
4. persisted input is rejected rather than trimmed, normalized, or aliased.

These tests deliberately exercise the strict parser directly. The existing
composed live validator remains mandatory for freshness and complete lineage
equality, but locally derivable producer invariants should fail before a
non-canonical typed persisted object is returned.

## Non-overlap

This contract does not modify #194 source/tests/docs and does not take source
ownership. It is distinct from:

- #398 positive twin versions;
- #399 evidence capability-set equality;
- #400 INTRODUCED/WORSENED current-path presence;
- #401 resolution-id/effect lineage;
- #402 canonical evidence kind;
- #319 snapshot isolation.

No target interaction, evidence collection, tool execution, remediation/retest
execution, deployment, verdict creation, or attack-path mutation is introduced.
