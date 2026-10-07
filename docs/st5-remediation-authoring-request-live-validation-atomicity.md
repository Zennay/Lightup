# ST5 remediation authoring-request live-validation atomicity

This tests/docs-only acceptance slice is based on exact active authoring-request
handoff PR #198 at `7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

It proves that the composed
`load_and_validate_future_remediation_authoring_request` boundary stays
read-only across strict parsing and full live-lineage validation.

## Contract

For a real remediation-authoring request:

- repeated successful load + live validation returns the exact canonical request;
- the persisted caller dictionary remains unchanged;
- caller-owned bundle, plan, report, preview, proposal, resolution and context
  values remain unchanged;
- live evidence rows remain unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, and
  `StateStore.add_evidence` are fail-fast sentinels and are never invoked;
- after deliberate ledger SHA drift, repeated rejection is deterministic and
  leaves persisted input, typed lineage and the already-stale evidence row
  unchanged;
- `authoring_requested=true` remains the only positive workflow fact;
  remediation proposal creation and all code/tool/execution/target/retest/
  deployment/attack-path authority remain false.

## Boundary

This changes no production source. It does not modify #198/#196/#60 source or
existing tests/docs, #447/#448, or the persisted canonicality acceptance work.

No model invocation, evidence collection, target interaction, code/config
generation, tool/remediation/retest execution, deployment, security verdict
creation, or attack-path mutation occurs.

Refs #449.
