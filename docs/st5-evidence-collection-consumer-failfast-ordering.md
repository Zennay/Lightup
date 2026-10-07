# ST5 evidence-collection consumer fail-fast ordering

Issue #749 isolates ordering at the persisted evidence-collection consumer from
PR #136.

## Invariant

Persisted-input validation must complete before live-lineage validation is
eligible to run. Invalid persisted data therefore fails at the earliest owning
boundary and cannot reach
`validate_future_security_evidence_collection_request()`.

The dedicated regression replaces that live validator with a sentinel that must
never be called and covers:

- malformed JSON text;
- duplicate JSON object keys;
- non-object JSON;
- unsupported persisted value types;
- exact-schema violations after JSON/object acceptance;
- canonical-shape request digest mismatch after strict traversal.

The first four cases exercise the outer persisted boundary. The latter two prove
that strict #64 parsing still completes before the live validator becomes
reachable.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #136 exact head
`931d71ad393df9cdfbcc3e068e65c20f3c0a7227`.

PR #136 retains consumer source ownership. #747 owns exact outer runtime-type
subclass rejection; #611/#746 own direct #64 persisted-object exactness; #318
owns snapshot isolation; #323/#329 own parser input purity. No production source
from those lanes is modified here.

## Safety

This is fail-fast ingestion-order evidence only. It grants no evidence
collection, capability/tool selection, target interaction, remediation/retest
execution, deployment, classification, verdict creation, or attack-path
mutation.
