# ST5 evidence-collection direct-construction integrity

Issue: #745  
Pinned acceptance parent: PR #62 at `04f3f010756e7609707fda467f8ab1809f361ae4`

## Contract

The typed evidence-collection artifacts are part of the safety boundary, not merely
serialization containers. Direct construction and `dataclasses.replace()` must
therefore preserve the same producer invariants that the canonical #62 builder
emits and that the later strict #64 persistence handoff validates.

For `FutureSecurityEvidenceCollectionRequest`:

- schema version is exact;
- lineage SHA-256 fields and `request_sha256` are canonical;
- the request digest remains coherent with the complete typed request;
- item container is an exact non-empty tuple of exact evidence-collection item
  objects and `evidence_gap_count` equals its length;
- twin versions and gap count are exact non-negative integers, never booleans;
- every collection/tool/execution/target/remediation/retest/deployment/attack-path
  authority flag is exactly the built-in boolean `False`;
- `future_semantics` remains exactly `unresolved`;
- `security_verdict` remains exactly `not_evaluated`.

For `FutureSecurityEvidenceCollectionItem`:

- identity fields are non-empty and the resolution digest is canonical;
- current-path lineage stays tuple-backed, while effect, prior-evidence and
  prior-capability provenance stay non-empty immutable tuples;
- `classification` remains exactly `insufficient_evidence`;
- `graph_diff_action` remains exactly `no_graph_change_claim`;
- `collection_reason` remains exactly `insufficient_evidence`;
- fresh evidence and a fresh run are exactly the built-in boolean `True`, never
  integer lookalikes;
- remediation authoring and future-state retest authority are exactly the built-in
  boolean `False`, never integer lookalikes.

The canonical builder output is the green control. Directly widened, weakened or
structurally incoherent typed artifacts must fail during construction rather than
relying on persistence or live consumers to rediscover invalid state.

## Expected state on the pinned #62 head

The canonical builder control is green.

The direct-construction rejection cases are expected RED because the two frozen
dataclasses currently have no `__post_init__` invariant checks. This acceptance
branch intentionally makes no production/source change.

## Ownership and non-overlap

#62 introduced the producer dataclasses, while stacked #64 also modifies the same
source module for strict persisted parsing. This branch therefore owns **only**
the tests/docs acceptance contract. It does not claim or modify either active
source surface.

It also does not modify #136 persisted live consumption, #66+ freshness/admission
layers, parser input-purity work (#324/#331), snapshot work (#318), scope
authorization, target interaction, remediation/retest execution, deployment,
verdict creation or attack-path mutation.

Any eventual source absorption must be coordinated with the then-current owner of
`src/lightup/future_security_evidence_collection_request.py` after the dependency
stack is ready; this branch must not overwrite #62/#64 work.

## Safety

Pure in-memory typed-artifact integrity proof. No network or DNS I/O, evidence
collection, capability/tool selection, target interaction, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
