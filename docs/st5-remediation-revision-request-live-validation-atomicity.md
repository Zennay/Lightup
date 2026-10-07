# ST5 remediation revision-request live-validation atomicity

This tests/docs-only acceptance slice is based on exact active remediation
text revision-request handoff PR #231 at
`30ebbd9f335bcbbc0ab076d344b79d94be8434e6`.

It proves that
`load_and_validate_future_remediation_text_revision_request` remains
read-only and repeatable across the persisted revision-request/review/
review-request/proposal chain and the complete live evidence-remediation
lineage.

## Contract

Using the real revision-required remediation fixture:

- repeated successful load + validation returns the exact canonical revision
  request;
- caller-owned persisted revision-request, review, review-request, and proposal
  dictionaries remain unchanged;
- caller-owned typed review/request/bundle/plan/report/preview/transition/
  resolution/context values remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage, and already-stale evidence
  state unchanged;
- persisted validation invokes no remediation model;
- `revision_requested=true` remains planning/review state only and every
  code/tool/execution/target/retest/deployment/attack-path authority flag stays
  false.

## Boundary

This changes no production source and does not overlap #238/#456
revision-proposal ownership, downstream revised-review work, earlier atomicity
slices, scope authorization, gateway behavior, or target-capable code.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #460.
