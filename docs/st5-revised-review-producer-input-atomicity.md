# ST5 revised reviewer producer input atomicity

This tests/docs-only acceptance slice is based on exact active revised
remediation review producer PR #246 at
`d995cf57e20f99956fe20b9b8b05d41b64e02765`.

It proves that `review_future_remediation_text_revision` preserves
caller-owned persisted/live revision lineage and the evidence ledger around its
one bounded verifier request.

## Contract

Using the real revised-remediation review fixture and recording verifier
provider:

- repeated successful reviews with identical verifier responses return the same
  canonical revised review;
- caller-owned persisted revised-review-request, revised-proposal,
  revision-request, prior-review, prior-review-request, and prior-proposal
  dictionaries remain unchanged;
- typed request/bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- each successful review issues exactly one bounded VERIFIER request;
- after deliberate ledger SHA drift, repeated rejection is deterministic,
  preserves persisted/typed/stale-state input, and invokes the verifier zero
  times;
- approved revised prose may set `remediation_accepted=true`, but every
  code/tool/execution/target/retest/deployment/attack-path authority flag
  remains false.

## Boundary

This is producer-side coverage and is distinct from #458 persisted revised
review live-validation atomicity and revised reviewer canonicality slices. It
changes no production source.

No evidence collection, target interaction, code/config application,
tool/remediation/retest execution, deployment, verdict creation, or attack-path
mutation occurs.

Refs #466.
