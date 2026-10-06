# ST5 remediation/retest handoff live-validation input atomicity

This tests/docs-only child proves that the existing #190 live handoff validator
consumes a typed remediation/retest plan and its live ST4 lineage without
rewriting caller-owned objects or persistent state.

## Boundary

The contract is intentionally separate from adjacent evidence-remediation work:

- strict parser purity covers caller-owned persisted dictionaries;
- direct-construction hardening covers typed plan invariants;
- builder input atomicity covers the remediation/retest plan producer;
- this proof covers `validate_future_security_remediation_retest_plan_handoff`
  after a typed plan already exists.

The closed standalone consumer work from #192 remains superseded; no separate
consumer implementation is revived here.

## Successful live validation

For every canonical ST4 classification, the regression creates the real
remediation/retest plan and snapshots:

- the typed plan, report, graph preview, transition proposal, resolution tuple,
  and `RunContext` tuple by value;
- nested tuple/list/dict/set/frozenset identities reachable from those
  caller-owned typed values;
- all persisted `runs`, `capability_leases`, and `evidence` rows.

During validation, the write-capable `StateStore` APIs `create_run`,
`acquire_lease`, and `add_evidence` are fail-fast sentinels. Two consecutive
live validations must return plans equal to the supplied plan while every input,
container identity, ledger row, and write sentinel remains unchanged.

## Cross-lineage rejection

A valid typed plan from one producer lineage is then checked against a distinct
valid live lineage. The equality gate must reject it twice with the same
fail-closed boundary.

That rejection must leave both the supplied plan and the alternate report,
preview, proposal, resolutions and contexts unchanged, with no live-state write.

## Safety boundary

The validated/rejected plan cannot acquire authority through this boundary:

- `execution_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No evidence collection, model invocation, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
