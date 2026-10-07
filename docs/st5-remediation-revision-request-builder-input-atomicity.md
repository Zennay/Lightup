# ST5 remediation revision-request builder input atomicity

This tests/docs-only acceptance slice is based on exact active remediation
revision-request producer PR #225 at
`d5a4d49e917c0b0b528bfd5ba68c54d124cfd569`.

It proves that `build_future_remediation_text_revision_request` is
deterministic and read-only across caller-owned persisted review lineage,
typed live inputs, and the evidence ledger.

## Contract

Using the real revision-required remediation review fixture:

- repeated successful construction returns the same canonical revision request;
- caller-owned persisted review, review-request, and proposal dictionaries
  remain unchanged;
- typed request/bundle/plan/report/preview/transition/resolution/context values
  remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage, and already-stale evidence
  state unchanged;
- construction itself invokes no model;
- `revision_requested=true` remains planning/review state only and every
  code/tool/execution/target/retest/deployment/attack-path authority flag stays
  false.

## Boundary

This is producer-side coverage and is distinct from #460, which owns the later
strict persisted revision-request handoff plus live-validation boundary. It
changes no production source and does not overlap downstream
revision-proposal/revised-review work, scope authorization, gateway behavior,
or target-capable code.

No model invocation during construction, evidence collection, target
interaction, code/config application, tool/remediation/retest execution,
deployment, verdict creation, or attack-path mutation occurs.

Refs #463.
