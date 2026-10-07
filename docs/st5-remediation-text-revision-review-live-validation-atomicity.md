# ST5 revised-review live-validation atomicity

This tests/docs-only acceptance slice is based on exact active revised
remediation review handoff PR #248 at
`546716d6117918dbbb12a0720f7659b6a59ff002`.

It proves that
`load_and_validate_future_remediation_text_revision_review` remains read-only
and repeatable while traversing the complete persisted revision-review chain
and live evidence-remediation lineage.

## Contract

Using the real approved revised-review producer fixture:

- repeated successful load + validation returns the exact canonical revised
  review;
- caller-owned persisted revised-review, revised-review-request,
  revised-proposal, revision-request, prior-review, prior-review-request and
  prior-proposal dictionaries remain unchanged;
- the corresponding typed lineage plus request, bundle, plan, report, preview,
  transition proposal, resolution and context remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving all persisted input, typed lineage and already-stale evidence
  state unchanged;
- persisted validation invokes no reviewer/model;
- approved revised prose may retain `remediation_accepted=true`, but all
  code/tool/execution/target/retest/deployment/attack-path authority remains
  false.

## Boundary

This changes no production source and does not overlap #437/#438 revised
reviewer-model canonicality, #445/#446 revised-summary canonicality, or earlier
atomicity acceptance slices.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #457.
