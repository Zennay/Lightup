# ST5 remediation evidence-bundle live-validation atomicity

This acceptance slice is a tests/docs-only child of exact active remediation
evidence-bundle handoff PR #194 at
`ec4b09f539289fbf3b497a534980323bd3c11bef`.

It covers the composed
`load_and_validate_future_remediation_evidence_bundle` boundary. The strict
parser and snapshot-detachment contract are already owned elsewhere (#319);
this slice instead proves that the subsequent live-lineage validation step is
read-only and repeatable.

## Contract

For a real #60 remediation evidence-bundle producer fixture:

- repeated successful load + live validation returns the exact canonical bundle;
- caller-owned proposal, context, resolution, preview, report and plan values
  remain unchanged;
- the caller-owned persisted dictionary remains unchanged;
- the live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease` and
  `StateStore.add_evidence` are fail-fast sentinels and are never called;
- after deliberate ledger SHA drift, repeated rejection is deterministic and
  does not mutate the persisted payload, typed live lineage or already-stale
  evidence row;
- successful validation preserves all planning-only stop lines:
  execution/code-change/target/deployment/attack-path authority is false,
  future semantics remain `unresolved`, and the security verdict remains
  `not_evaluated`.

## Boundary

This changes no production source and does not overlap #194/#60 source
ownership, #319 snapshot isolation, or the persisted canonicality acceptance
work in #398-#446.

The proof is deliberately read-only. It performs no evidence collection, model
invocation, target interaction, remediation or retest execution, deployment,
security verdict creation, or attack-path mutation.

Refs #447.
