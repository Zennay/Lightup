# ST5 remediation review-request builder input atomicity

This tests/docs-only acceptance slice is based on exact active remediation
review-request producer PR #213 at
`fe5f9cca5db890b2ae44814a93b1441a8ef598cc`.

It proves that `build_future_remediation_text_review_request` is deterministic
and read-only across caller-owned persisted proposal input, typed live lineage,
and the evidence ledger.

## Contract

Using the real remediation-text proposal fixture:

- repeated successful construction returns the same canonical review request;
- the caller-owned persisted proposal dictionary remains unchanged;
- typed request/bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage, and already-stale evidence
  state unchanged;
- construction invokes no model;
- `review_requested=true` remains review intent only and remediation
  acceptance plus every action-authority flag remain false.

## Boundary

This is producer-side coverage and is distinct from #459, which owns the later
strict persisted handoff plus live-validation boundary. It changes no
production source and does not overlap downstream review/revision work, scope
authorization, gateway behavior, or target-capable code.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #462.
