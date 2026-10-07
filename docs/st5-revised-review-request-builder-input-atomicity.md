# ST5 revised review-request builder input atomicity

This tests/docs-only acceptance slice is based on exact active revised
remediation review-request producer PR #242 at
`27e26f200becf14738b9b1bc7af05e2476d0971a`.

It proves that `build_future_remediation_text_revision_review_request` is
deterministic and read-only across caller-owned persisted revision lineage,
typed live inputs, and the evidence ledger.

## Contract

Using the real revised-remediation proposal fixture:

- repeated successful construction returns the same canonical revised review
  request;
- caller-owned persisted revised-proposal, revision-request, prior-review,
  prior-review-request, and prior-proposal dictionaries remain unchanged;
- typed request/bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage, and already-stale evidence
  state unchanged;
- construction itself invokes no model;
- `review_requested=true` remains review intent only and remediation
  acceptance plus every action-authority flag remain false.

## Boundary

This is producer-side coverage and is distinct from #461, which owns the later
strict persisted revised-review-request handoff plus live-validation boundary.
It changes no production source and does not overlap #248/#458 revised-review
ownership, earlier atomicity slices, scope authorization, gateway behavior, or
target-capable code.

No model invocation during construction, evidence collection, target
interaction, code/config application, tool/remediation/retest execution,
deployment, verdict creation, or attack-path mutation occurs.

Refs #464.
