# ST4 transition-verification evidence input integrity

Issue #866 closes the remaining polymorphic input gap for fresh ST4 transition evidence.

## Gap

The public transition-verification builder previously did:

```python
evidence_ids = tuple(sorted(evidence_ids))
```

before the resolution shape was validated. That repairs a caller list or tuple subclass into a canonical tuple instead of failing at the public boundary. The later canonical tuple validator also used `isinstance(values, tuple)`, while identifier validation accepts `str` subclasses.

A directly supplied resolution could therefore preserve polymorphic evidence identifiers while producing the same JSON/digest material as canonical built-in strings.

## Contract

Transition-verification evidence IDs now have an exact type boundary before any sorting or digest work:

- the container is an exact built-in `tuple`;
- every member is an exact built-in `str`.

After that boundary, all existing semantics remain unchanged:

- the builder may canonically sort an exact tuple;
- evidence remains required, bounded and unique;
- live evidence must be fresh;
- StateStore records must match the exact run, metadata contract and capability set;
- resolution digest and stable identity validation remain mandatory.

Live revalidation enforces the same exact evidence tuple/member identity before canonical tuple and digest checks, so tuple/string subclasses cannot survive merely because they serialize identically.

## Non-overlap

This slice intentionally does not change `capability_ids`, `effect_ids`, `current_attack_path_ids`, action/classification compatibility, evidence collection, evidence metadata schema, target behavior, remediation/retest execution, deployment, verdict or attack-path mutation.

## Safety

Fresh-evidence input integrity only. No target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
