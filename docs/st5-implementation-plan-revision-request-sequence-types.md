# ST5 implementation-plan revision-request sequence types

## Scope

This tests/docs-only acceptance slice is a child of the strict
implementation-plan revision-request handoff in #501.

- exact parent head: `81cd78f074a777a0380672050082fd21616a447c`
- acceptance issue: #536
- production/source changes: **0**

It is separate from #510 outer mapping typing, #516 reviewer provenance,
#522 SHA scalar typing, #506 parser input-purity, #507 live-validation
atomicity, #486 builder atomicity, #528/#529 direct typed-object metadata,
#530/#531 direct revision-check item types, and #534/#535 snapshot isolation.

## Invariant

The persisted `required_revisions` container must be an exact supported
built-in sequence before the parser iterates or materializes it.

The current #501 handoff accepts values through
`isinstance(value, (list, tuple))` and then converts them with
`tuple(value)`. A polymorphic list can therefore retain producer-impossible
stored content while overriding iteration to present the canonical rubric
subset used by validation.

The regression requires:

- an exact built-in list containing canonical revision checks remains accepted;
- a list subclass is rejected before polymorphic iteration can substitute
  parser-visible values for the caller-owned stored values;
- rejection does not normalize or mutate the persisted caller object.

## Authority stop line

This contract changes no workflow authority. The artifact remains a
planning-only revision request: no revised plan, code/config change, tool call,
execution, target interaction, remediation, retest, deployment, attack-path
mutation, future-state resolution, or security verdict is authorized.

## Safety

Pure in-memory persistence-integrity proof only. No model invocation, target
interaction, scanning, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
