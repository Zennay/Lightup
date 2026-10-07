# ST5 revision-proposal producer input atomicity

This tests/docs-only acceptance slice is based on exact active remediation
revision-proposal producer PR #234 at
`7156a6dc00b79c1cfb87c2fe783a957e2e81ecf7`.

It proves that `generate_future_remediation_text_revision_proposal` preserves
caller-owned persisted revision/prior-review lineage, typed live inputs, and
the evidence ledger around its one bounded REMEDIATION_ADVISOR request.

## Contract

Using the real revision-required remediation fixture and recording provider:

- repeated successful generation with identical model responses returns the
  same canonical revision proposal;
- caller-owned persisted revision-request, prior-review, prior-review-request,
  and prior-proposal dictionaries remain unchanged;
- typed request/bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- each successful generation issues exactly one bounded REMEDIATION_ADVISOR
  request;
- after deliberate ledger SHA drift, repeated rejection is deterministic,
  preserves persisted/typed/stale-state input, and invokes the model zero
  times;
- `remediation_revision_proposal_created=true` remains unaccepted
  planning/prose state and every action-authority flag remains false.

## Boundary

This is producer-side coverage and is distinct from #456 persisted
revision-proposal live-validation atomicity plus revision model/content
canonicality slices. It changes no production source.

No evidence collection, target interaction, code/config application,
tool/remediation/retest execution, deployment, verdict creation, or attack-path
mutation occurs.

Refs #468.
