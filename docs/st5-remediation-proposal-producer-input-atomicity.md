# ST5 remediation proposal producer input atomicity

This tests/docs-only acceptance slice is based on exact active remediation
text-proposal producer PR #207 at
`eaf03f3b672867ef3a22107e3c03ceeaedfb5ef7`.

It proves that `generate_future_remediation_text_proposal` preserves
caller-owned typed live lineage and the evidence ledger around its one bounded
REMEDIATION_ADVISOR request.

## Contract

Using the real remediation authoring fixture and recording provider:

- repeated successful generation with identical model responses returns the
  same canonical proposal;
- caller-owned request/bundle/plan/report/preview/transition/resolution/context
  values remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- each successful generation issues exactly one bounded REMEDIATION_ADVISOR
  request;
- after deliberate ledger SHA drift, repeated rejection is deterministic,
  preserves typed/stale-state input, and invokes the model zero times;
- `remediation_proposal_created=true` remains planning/prose state only and
  every code/tool/execution/target/retest/deployment/attack-path authority flag
  remains false.

## Boundary

This is producer-side coverage and is distinct from #452 persisted proposal
live-validation atomicity plus #428/#440 model/content canonicality. It changes
no production source.

No evidence collection, target interaction, code/config application,
tool/remediation/retest execution, deployment, verdict creation, or attack-path
mutation occurs.

Refs #467.
