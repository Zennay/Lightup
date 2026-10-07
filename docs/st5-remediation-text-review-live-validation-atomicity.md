# ST5 remediation review live-validation atomicity

This tests/docs-only acceptance slice is based on exact active remediation-text
review handoff PR #220 at
`82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

It proves that
`load_and_validate_future_remediation_text_review` remains read-only and
repeatable while traversing all three persisted review-chain inputs and the
full live evidence-remediation lineage.

## Contract

Using the real approved independent-review producer fixture:

- repeated successful load + validation returns the exact canonical review;
- caller-owned persisted review, review-request and proposal dictionaries remain
  unchanged;
- typed review-request/proposal plus request, bundle, plan, report, preview,
  transition proposal, resolution and context remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving all persisted input, typed lineage and already-stale evidence
  state unchanged;
- persisted review validation invokes no reviewer/model;
- approved prose may retain `remediation_accepted=true`, but code/tool/
  execution/target/retest/deployment/attack-path authority remains false.

## Boundary

This changes no production source and does not overlap #432/#434 reviewer-model
canonicality, #441/#442 summary canonicality, or the upstream atomicity
acceptance slices.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #453.
