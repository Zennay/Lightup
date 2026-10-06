# ST5 remediation/retest parse-to-live-validation chain atomicity

This tests/docs-only regression proves that the documented #190 persisted
handoff sequence remains read-only when its strict parser and live validator are
composed.

## Composition boundary

The sequence under proof is:

`caller-owned dictionary -> strict typed parse -> live lineage validation`

The isolated boundaries remain independently owned:

- #354 proves the strict dictionary parser preserves caller input;
- #352 proves the typed live validator preserves caller-owned typed lineage;
- this contract proves that using those boundaries consecutively does not
  introduce an intermediate mutation, ledger write, or authority widening.

No #190 production source or existing test is changed.

## Successful composed flow

For each canonical ST4 classification, the regression creates the real
remediation/retest plan, JSON-decodes it to a caller-owned dictionary, then
records:

- a deep snapshot of the persisted dictionary and all typed live-lineage inputs;
- the caller dictionary's byte-stable key/list ordering;
- recursive dict/list/tuple/set/frozenset container identities;
- all live `runs`, `capability_leases`, and `evidence` rows.

The same caller-owned payload is parsed and live-validated twice. Both results
must equal the original producer plan, while every caller-owned value,
container identity, ordering snapshot, and live ledger row remains unchanged.

During live validation, `StateStore.create_run`, `acquire_lease`, and
`add_evidence` are fail-fast sentinels, so a temporary write cannot be hidden
by restoring the final database contents.

## Cross-lineage rejection

A valid persisted plan from one lineage is parsed successfully and then checked
against a second valid lineage. The live equality gate must reject that
cross-lineage substitution twice with the same failure while preserving:

- the original caller-owned persisted dictionary;
- the original typed plan;
- the alternate report/preview/proposal/resolution/context inputs;
- all recursive caller-owned container identities;
- every live ledger row and write sentinel.

## Safety stop line

Composition cannot create action authority:

- `execution_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

This proof performs no evidence collection, model invocation, target
interaction, tool/remediation/retest execution, deployment, verdict creation,
or attack-path mutation.
