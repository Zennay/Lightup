# ST5 freshness-coverage consumer success input atomicity

Issue #760 isolates success-path caller-input atomicity at the composed persisted
freshness-coverage consumer from PR #128.

## Invariant

A valid caller-owned JSON-decoded coverage payload must remain observationally
unchanged after strict parsing and immediate live-lineage validation.

The regression records the complete value, recursive dict/list object identities
and key/list ordering, consumes the exact same object twice, and requires each
result to equal the canonical producer coverage while all persisted-input
snapshots remain unchanged.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #128 exact head
`fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57`.

PR #128 retains source ownership. #758 owns rejection-path atomicity; #757 owns
fail-fast ordering; #755 owns outer runtime-type exactness; #619 owns direct
strict-parser exactness.

## Safety

This is success-path freshness-coverage input-integrity evidence only. It grants
no evidence sufficiency decision, classification, transition, collection,
target interaction, remediation/retest execution, deployment, verdict creation,
or attack-path mutation.
