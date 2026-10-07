# ST5 remediation authoring-request builder input atomicity

This tests/docs-only acceptance slice is based on exact active authoring-request
producer PR #196 at
`f559e28e4ce213daa831effed95e671154ba5d8e`.

It proves that `build_future_remediation_authoring_request` is deterministic
and read-only across caller-owned evidence-bundle/live-lineage input and the
evidence ledger.

## Contract

Using the real INTRODUCED remediation-evidence fixture:

- repeated successful construction returns the same canonical authoring
  request;
- caller-owned bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection is deterministic while
  typed lineage and already-stale evidence state remain unchanged;
- construction invokes no model;
- `authoring_requested=true` remains planning state only:
  `remediation_proposal_created=false` and every action-authority flag stays
  false.

## Boundary

This is producer-side coverage and is distinct from #450 persisted
authoring-request live-validation atomicity. It changes no production source
and does not overlap evidence-bundle producer-invariant branches, downstream
proposal/review/revision work, scope authorization, gateway behavior, or
target-capable code.

No model invocation, evidence collection after fixture setup, target
interaction, code/config application, tool/remediation/retest execution,
deployment, verdict creation, or attack-path mutation occurs.

Refs #469.
