# ST5 freshness-coverage consumer rejection input atomicity

Issue #758 isolates caller-input atomicity at the composed persisted
freshness-coverage consumer from PR #128.

## Invariant

A caller-owned JSON-decoded coverage payload must remain observationally
unchanged when the consumer fails closed, whether rejection happens during
strict parsing or during immediate live-lineage validation.

The regression captures the complete value, recursive dict/list object
identities and key/list ordering, then proves repeated rejection cannot mutate or
normalize the same caller-owned object.

Covered stages:

1. strict coverage-digest rejection; and
2. live rejection after deliberately drifting the evidence-ledger SHA used by
   the canonical coverage lineage.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #128 exact head
`fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57`.

PR #128 retains source ownership. #757 owns fail-fast ordering; #755 owns outer
runtime-type exactness; #619 owns direct strict-parser exactness. The
freshness-constraints consumer lane remains separate.

## Safety

This is input-integrity proof only. It grants no evidence sufficiency decision,
classification, transition, collection, target interaction, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
