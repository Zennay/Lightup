# ST5 remediation authoring-request top-level lineage acceptance

This tests/docs-only acceptance contract sits directly above the exact active
#198 remediation-authoring request handoff head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Gap

The strict persisted parser checks these top-level lineage fields with a generic
non-empty-string predicate:

- `client_id`;
- `current_twin_id`;
- `twin_id`;
- `changeset_id`.

The upstream remediation/retest-plan producer contract (#381/#382) already
requires these identities to be canonical: non-empty, already trimmed, free of
ASCII control characters and DEL, and at most 256 characters. The authoring
request copies this lineage through the evidence-bundle chain.

A persisted caller can currently substitute padded, control-character-bearing
or overlong lineage text and recompute `request_sha256`. Digest integrity alone
therefore does not preserve producer-reachable top-level identity shape.

## Acceptance

The regression requires:

1. an untouched real WORSENED producer request still round-trips;
2. each of the four top-level lineage fields rejects padded text;
3. each rejects control-character-bearing text;
4. each rejects text longer than 256 characters;
5. every forged case carries a recomputed matching `request_sha256`;
6. persisted input is rejected rather than normalized.

This exercises the strict parser directly. Complete live lineage revalidation
remains mandatory after parsing.

## Non-overlap

Issue #425 does not modify #198 source/tests/docs and does not take source
ownership. It is distinct from #410/#412/#414/#416/#418/#420/#422 and from the
upstream evidence-bundle top-level lineage acceptance #423/#424.

No model invocation, target interaction, code/config generation, tool execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.

## Expected state

Until #198's source owner absorbs this narrow invariant, the canonical producer
control should remain green while the 12 forged cases are expected RED. The
post-fix target is 12 RED -> 0 RED with the parent handoff and safety canaries
unchanged.
