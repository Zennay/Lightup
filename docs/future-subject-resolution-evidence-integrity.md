# Future subject-resolution evidence integrity

Issue #864 narrows the typed input boundary for `FutureSubjectResolution.evidence_ids`.

## Gap

Subject-resolution evidence IDs already have strong value-level validation: they are required, bounded, free of surrounding whitespace and control characters, and unique.

The remaining gap was Python type identity. The container was not required to be an exact tuple, and the shared bounded-string validator intentionally uses `isinstance(value, str)`. That allowed list/tuple-subclass containers and `str` subclasses to cross the resolution input boundary before StateStore lookup and Security Twin evidence projection.

## Canonical contract

The resolution input now additionally requires:

- `evidence_ids` is an exact built-in `tuple`;
- every member is an exact built-in `str` before existing identifier validation.

All existing rules remain unchanged:

- at least one and at most 16 evidence IDs;
- bounded canonical identifiers;
- no surrounding whitespace or control characters;
- uniqueness;
- exact run/evidence-metadata/basis/candidate/tenant lineage at application time.

No value is trimmed, stringified, sorted, deduplicated or repaired.

## Non-overlap

This slice does not change verified snapshot validation, candidate binding, evidence metadata contracts, subject-selection semantics, Security Twin core validation (#858/#859), materialization/effect evidence validation (#860/#861), target-capable code, deployment, verdict or attack-path mutation.

## Safety

Immutable ST3 evidence-input narrowing only. No target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
