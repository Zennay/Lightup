# ST5 freshness-coverage consumer fail-fast ordering

Issue #757 isolates ordering at the persisted freshness-coverage consumer from
PR #128.

## Invariant

Persisted-input validation must finish before the live coverage validator can
run. Invalid persisted data must therefore fail at its owning serialization or
strict-parser boundary instead of reaching live-lineage validation.

The regression replaces
`validate_future_security_evidence_freshness_coverage()` with a sentinel that
must never be called and covers:

- malformed JSON text;
- duplicate JSON object keys;
- non-object JSON;
- unsupported persisted value types;
- exact-schema rejection after JSON/object acceptance;
- canonical-shape coverage-digest rejection after strict traversal.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #128 exact head
`fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57`.

PR #128 retains source ownership. #755 owns outer runtime-type subclass
exactness; #619 owns direct strict-parser exactness. The freshness-constraints
consumer lane (#748/#754/#756) remains separate.

## Safety

This is fail-fast freshness-coverage ingestion evidence only. It grants no
evidence sufficiency decision, classification, transition, collection, target
interaction, remediation/retest execution, deployment, verdict creation, or
attack-path mutation.
