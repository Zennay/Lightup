# ST5 remediation text-proposal live-validation atomicity

This tests/docs-only acceptance slice is based on exact active remediation text
proposal handoff PR #209 at
`38c40d112751728c238dcf5d7ab556079528c38e`.

It proves that
`load_and_validate_future_remediation_text_proposal` remains read-only and
repeatable across strict persisted parsing plus full live authoring-lineage
validation.

## Contract

Using the real bounded remediation-text producer fixture:

- repeated successful load + validation returns the exact canonical proposal;
- the caller-owned persisted proposal dictionary remains unchanged;
- request, bundle, plan, report, preview, transition proposal, resolution and
  context values remain unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection returns the same error
  while leaving persisted input, typed lineage and already-stale evidence state
  unchanged;
- persisted proposal validation never invokes the model gateway;
- `remediation_proposal_created=true` remains prose/planning state only and
  all code/tool/execution/target/retest/deployment/attack-path authority stays
  false.

## Boundary

This changes no production source and does not overlap #427/#428 model identity,
#439/#440 content canonicality, or upstream #447/#448 and #449/#450 atomicity
proofs.

No model invocation, evidence collection, target interaction, code/config
application, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.

Refs #451.
