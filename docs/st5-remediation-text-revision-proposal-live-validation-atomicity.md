# ST5 revision-proposal live-validation atomicity

This tests/docs-only acceptance slice is based on exact active revised
remediation proposal handoff PR #238 at
`ef38622caf8c63be34785f971d0526e85740b55d`.

It proves that
`load_and_validate_future_remediation_text_revision_proposal` remains
read-only and repeatable across the complete persisted revision chain and live
evidence-remediation lineage.

## Contract

Using the real revised-proposal producer fixture:

- repeated successful load + validation returns the exact canonical revised
  proposal;
- caller-owned persisted revised-proposal, revision-request, review,
  review-request and prior-proposal dictionaries remain unchanged;
- typed revision/review/prior-proposal state plus request, bundle, plan, report,
  preview, transition proposal, resolution and context remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage and already-stale evidence state
  unchanged;
- persisted validation invokes no remediation model;
- revised prose remains unaccepted and all code/tool/execution/target/retest/
  deployment/attack-path authority remains false.

## Boundary

This changes no production source and does not overlap #435/#436 revision
model-identity canonicality, #443/#444 revised-content canonicality, or earlier
atomicity acceptance slices.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #455.
