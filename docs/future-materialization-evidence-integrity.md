# Future materialization evidence integrity

Issue #861 narrows the ST3 `FutureMaterializationResolution.evidence_ids` typed-object boundary.

## Gap

Materialization evidence is used twice:

1. to resolve durable evidence rows from `StateStore`; and
2. to create Security Twin evidence references through `f"evidence:{item}"`.

Before this change, the resolution only required evidence to be present and unique. It did not enforce the tuple/member types, so malformed values could be accepted until a later lookup or even be stringified into apparently normal twin evidence lineage.

## Canonical contract

`evidence_ids` now requires:

- an exact built-in `tuple`;
- at least one member;
- exact built-in `str` members only;
- non-blank members;
- unique members.

Validation does not trim, stringify, sort, deduplicate or otherwise repair caller input.

All existing materialization provenance checks remain unchanged: referenced evidence must still belong to the exact run/client/engagement/mode and its capabilities must exactly match `capability_ids`.

## Non-overlap

This slice intentionally does not change:

- `capability_ids` or `limitations`;
- RunContext or evidence provenance checks;
- materialization outcome/equivalence semantics;
- Security Twin evidence primitive validation (#858/#859);
- future-effect evidence validation (#860);
- remediation/retest planning or any target-capable path.

## Safety

Immutable ST3 evidence-lineage narrowing only. No target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
