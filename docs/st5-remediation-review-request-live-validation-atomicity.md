# ST5 remediation review-request live-validation atomicity

This tests/docs-only acceptance slice is based on exact active remediation
text review-request handoff PR #215 at
`cee2e5391f32eed5212424d778c66cae73042e4a`.

It proves that
`load_and_validate_future_remediation_text_review_request` remains read-only
and repeatable across strict persisted review-request/proposal input and the
complete live evidence-remediation lineage.

## Contract

Using the real remediation review-request producer fixture:

- repeated successful load + validation returns the exact canonical review
  request;
- caller-owned persisted review-request and proposal dictionaries remain
  unchanged;
- caller-owned proposal/request/bundle/plan/report/preview/transition/
  resolution/context values remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage, and already-stale evidence
  state unchanged;
- persisted validation invokes no remediation model;
- `review_requested=true` remains review intent only:
  `remediation_accepted=false` and every code/tool/execution/target/retest/
  deployment/attack-path authority flag remains false.

## Boundary

This changes no production source and does not overlap downstream #220/#454
review ownership, proposal atomicity #451/#452, persisted canonicality slices,
scope authorization, gateway behavior, or target-capable code.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #459.
