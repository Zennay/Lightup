# ST5 freshness-coverage live consumer read-only contract

Issue #761 isolates read-only behavior at the composed persisted
freshness-coverage consumer introduced by PR #128.

## Invariant

Strict parsing plus immediate live-lineage validation is an observation boundary.
It must not create or rewrite execution state and it must not mutate any supplied
typed lineage artifact.

The regression uses real #128 producer lineage and proves both canonical success
and fail-closed live rejection after deliberate evidence-ledger SHA drift.

For each path it snapshots the proposal, source context, transition resolution,
graph-diff preview, security-delta report, remediation/retest plan, evidence
collection request, freshness constraints, candidate context and freshness
admission, together with durable `runs`, `capability_leases` and `evidence`
rows.

Fail-fast sentinels on `StateStore.create_run`, `StateStore.acquire_lease`
and `StateStore.add_evidence` prove the consumer cannot repair or create state
as a validation side effect.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #128 exact head
`fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57`.

PR #128 retains source ownership. #760/#758 own persisted-input atomicity; #757
owns fail-fast ordering; #755 owns outer runtime-type exactness. The separate
freshness-constraints consumer remains outside this lane.

## Safety

This is read-only freshness-coverage validation evidence only. It grants no
evidence sufficiency decision, classification, transition, collection, target
interaction, remediation/retest execution, deployment, verdict creation, or
attack-path mutation.
