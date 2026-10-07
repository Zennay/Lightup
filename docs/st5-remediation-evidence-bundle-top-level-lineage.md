# ST5 remediation evidence-bundle top-level lineage acceptance

This tests/docs-only acceptance contract sits directly above the exact active
#194 remediation evidence-bundle handoff head
`ec4b09f539289fbf3b497a534980323bd3c11bef`.

## Gap

The strict persisted parser currently checks these top-level lineage fields with
a generic non-empty-string predicate:

- `client_id`;
- `current_twin_id`;
- `twin_id`;
- `changeset_id`.

That is weaker than the already-proven upstream remediation/retest-plan
producer contract. #381/#382 established that these identities must remain
canonical: non-empty, already trimmed, free of ASCII control characters and
DEL, and at most 256 characters.

A persisted caller can currently substitute padded, control-character-bearing
or overlong top-level lineage text and recompute the public `bundle_sha256`.
Digest integrity therefore does not by itself preserve producer-reachable
identity shape at this strict handoff.

## Acceptance

The regression contract requires:

1. an untouched real WORSENED producer bundle still round-trips;
2. each of the four top-level lineage fields rejects padded text;
3. each rejects control-character-bearing text;
4. each rejects text longer than 256 characters;
5. every forged case carries a recomputed matching `bundle_sha256`, so a stale
   digest cannot satisfy the test;
6. persisted input is rejected rather than trimmed or normalized.

This intentionally exercises the strict parser directly. The existing composed
live validator remains mandatory for current lineage equality, but locally
derivable producer invariants should fail before a non-canonical typed persisted
object is returned.

## Non-overlap

Issue #423 does not modify #194 source/tests/docs and does not take source
ownership. It is distinct from:

- #398 positive twin versions;
- #399 exact evidence/capability coverage;
- #400 classification/current-path semantics;
- #401 resolution/effect lineage;
- #402 canonical evidence kind;
- #405/#406 item/evidence identities;
- #407/#408 capability/path identities;
- #319 snapshot isolation.

No evidence collection, target interaction, model invocation, tool execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.

## Expected state

Until #194's source owner absorbs this narrow invariant, the canonical producer
control should stay green while the 12 forged lineage cases are expected RED.
After absorption, the target is 12 RED -> 0 RED without weakening the parent
handoff or safety canaries.
