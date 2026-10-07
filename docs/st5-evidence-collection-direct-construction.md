# ST5 evidence-collection direct-construction integrity

Issue: #745  
Pinned source owner: PR #62 at `04f3f010756e7609707fda467f8ab1809f361ae4`

## Contract

The typed evidence-collection artifacts are part of the safety boundary, not merely
serialization containers. Direct construction and `dataclasses.replace()` must
therefore preserve the same planning-only invariants as the canonical #62 builder.

For `FutureSecurityEvidenceCollectionRequest`:

- every collection/tool/execution/target/remediation/retest/deployment/attack-path
  authority flag is exactly the built-in boolean `False`;
- `future_semantics` remains exactly `unresolved`;
- `security_verdict` remains exactly `not_evaluated`.

For `FutureSecurityEvidenceCollectionItem`:

- `classification` remains exactly `insufficient_evidence`;
- `graph_diff_action` remains exactly `no_graph_change_claim`;
- `collection_reason` remains exactly `insufficient_evidence`;
- fresh evidence and a fresh run are exactly the built-in boolean `True`;
- remediation authoring and future-state retest authority are exactly the built-in
  boolean `False`.

The canonical builder output is the green control. Directly widened or weakened
typed artifacts must fail during construction rather than relying on a later
consumer to rediscover the invalid state.

## Expected state on the pinned #62 head

The canonical builder control is green.

The direct-construction rejection cases are expected RED because the two frozen
dataclasses currently have no `__post_init__` invariant checks. This acceptance
branch intentionally makes no production/source change; #62 remains the sole
source owner for this boundary.

## Non-overlap

This slice does not modify the #62 producer, #64 persisted handoff/parser, #136
persisted consumer, #66+ freshness/admission chain, parser input-purity work
(#324/#331), scope authorization, target interaction, remediation/retest
execution, deployment, verdict creation or attack-path mutation.

## Safety

Pure in-memory typed-artifact integrity proof. No network or DNS I/O, evidence
collection, capability/tool selection, target interaction, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
