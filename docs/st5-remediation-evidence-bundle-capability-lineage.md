# ST5 remediation evidence bundle capability-lineage acceptance

Issue #399 preserves the evidence-to-capability relationship already enforced by
the canonical remediation-evidence producer when a bundle crosses the persisted
#194 handoff.

## Producer contract

The #60 producer rereads every evidence record from live `StateStore` and
fails closed if the record's `capability_id` is outside the remediation item's
declared `capability_ids`. A canonical bundle therefore cannot contain an
evidence reference whose capability is absent from its enclosing item lineage.

The strict #194 parser currently validates both structures independently and
recomputes the evidence-manifest and bundle digests, but it does not reassert
that membership relationship.

## Acceptance

The positive control round-trips real INTRODUCED and WORSENED producer bundles.

The forged case changes only one nested evidence `capability_id` to a different
non-empty identifier that is absent from the item's `capability_ids`, then
recomputes both `evidence_manifest_sha256` and `bundle_sha256`. Strict
persisted parsing must still fail closed.

The parser must reject this contradiction rather than widening the item
capability union or normalizing the caller input. Full ledger freshness and
provenance remain the responsibility of the mandatory immediate live validator.

## Collision boundary

Tests/docs only, based directly on the active #194 handoff branch. No #194
source/tests/docs are modified.

This is distinct from #398 positive twin versions, #319 snapshot isolation,
the #59/#60 live producer implementation, and downstream remediation-authoring
request work.

## Safety

Persistence-integrity acceptance only. No evidence collection, model
invocation, target interaction, tool execution, remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
