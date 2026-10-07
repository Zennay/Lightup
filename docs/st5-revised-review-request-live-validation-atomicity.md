# ST5 revised review-request live-validation atomicity

This tests/docs-only acceptance slice is based on exact active revised
remediation review-request handoff PR #244 at
`7eb4f5f72f5656b5476ba8735d7e83ded06decf3`.

It proves that
`load_and_validate_future_remediation_text_revision_review_request` remains
read-only and repeatable across the complete persisted revised-review-request/
revision lineage and live evidence-remediation state.

## Contract

Using the real revised-remediation review-request producer fixture:

- repeated successful load + validation returns the exact canonical revised
  review request;
- caller-owned persisted revised-review-request, revised-proposal,
  revision-request, prior-review, prior-review-request, and prior-proposal
  dictionaries remain unchanged;
- all corresponding typed lineage plus request/bundle/plan/report/preview/
  transition/resolution/context values remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage, and already-stale evidence
  state unchanged;
- persisted validation invokes no model;
- `review_requested=true` remains review intent only:
  `remediation_accepted=false` and every code/tool/execution/target/retest/
  deployment/attack-path authority flag remains false.

## Boundary

This changes no production source and does not overlap #248/#458 revised-review
ownership, #238/#456 revision-proposal ownership, earlier atomicity slices,
scope authorization, gateway behavior, or target-capable code.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #461.
