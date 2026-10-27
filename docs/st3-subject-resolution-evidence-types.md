# ST3 subject-resolution evidence identifier types

Issue: #864

`FutureSubjectResolution.evidence_ids` is durable evidence lineage. The typed-object boundary must reject producer-impossible Python shapes instead of allowing later StateStore and Security Twin code to consume them.

## Invariant

- `evidence_ids` is an exact built-in `tuple`.
- At least one evidence identifier remains required.
- At most 16 evidence identifiers remain allowed.
- Every member is an exact built-in `str` before bounded-identifier validation.
- Existing whitespace, control-character, length and uniqueness checks remain unchanged.
- Input is never trimmed, stringified, sorted, deduplicated or repaired.

## Boundary

This slice changes only `FutureSubjectResolution.evidence_ids` validation. Candidate binding, evidence metadata, run/basis/tenant checks, Security Twin semantics, target-capable behavior, remediation/retest execution, deployment, verdicts and attack paths are unchanged.

## Safety

Immutable evidence-input narrowing only. No network or target interaction and no new execution authority.
