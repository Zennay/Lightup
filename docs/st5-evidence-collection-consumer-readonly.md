# ST5 evidence-collection live consumer read-only contract

Issue #752 isolates read-only behavior at the composed persisted
evidence-collection consumer introduced by PR #136.

## Invariant

Strict parsing plus immediate live-lineage validation is an observation boundary.
It must not create or rewrite execution state and it must not mutate any supplied
typed lineage artifact.

The dedicated regression uses the real #136 producer lineage and proves both:

1. canonical successful consumption; and
2. fail-closed live rejection after deliberate prior-evidence deletion.

For each path it snapshots the supplied proposal, run context, transition
resolution, graph-diff preview, security-delta report and remediation/retest
plan, together with the durable `runs`, `capability_leases` and `evidence`
rows.

It also installs fail-fast sentinels on `StateStore.create_run`,
`StateStore.acquire_lease` and `StateStore.add_evidence`. A consumer that
attempts any write therefore fails the regression immediately.

Repeated success or rejection must stay deterministic while all live typed
inputs and durable state remain unchanged from the pre-call snapshot.

## Collision boundary

This branch is tests/docs-only and is pinned directly to PR #136 exact head
`931d71ad393df9cdfbcc3e068e65c20f3c0a7227`.

PR #136 retains consumer source ownership. #751/#750 own caller-owned persisted
input atomicity, #749 owns fail-fast ordering, #747 owns outer runtime-type
exactness and #318 owns request snapshot isolation.

## Safety

This is read-only validation evidence only. It grants no evidence collection,
capability/tool selection, target interaction, remediation/retest execution,
deployment, classification, verdict creation, or attack-path mutation.
