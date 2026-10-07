# ST5 remediation reviewer producer input atomicity

This tests/docs-only acceptance slice is based on exact active remediation
review producer PR #217 at
`d7e3c1e5f21726a2dfd6bd9133e3823a06402160`.

It proves that `review_future_remediation_text` preserves caller-owned
persisted/live lineage and the evidence ledger around its one bounded verifier
request.

## Contract

Using the real remediation review fixture and recording verifier provider:

- repeated successful reviews with identical verifier responses return the same
  canonical review;
- caller-owned persisted review-request and proposal dictionaries remain
  unchanged;
- typed request/bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- each successful review issues exactly one bounded VERIFIER request;
- after deliberate ledger SHA drift, repeated rejection is deterministic,
  preserves persisted/typed/stale-state input, and invokes the verifier zero
  times;
- approved prose may set `remediation_accepted=true`, but every code/tool/
  execution/target/retest/deployment/attack-path authority flag remains false.

## Boundary

This is producer-side coverage and is distinct from #454 persisted-review
live-validation atomicity, #434 reviewer model-identity canonicality, and #442
review-summary canonicality. It changes no production source.

No evidence collection, target interaction, code/config application,
tool/remediation/retest execution, deployment, verdict creation, or attack-path
mutation occurs.

Refs #465.
