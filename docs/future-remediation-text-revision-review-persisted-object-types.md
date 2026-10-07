# ST5 revised-remediation review persisted object type exactness

Issue #627 isolates persisted-object type fidelity above strict revised-remediation review handoff #248 at exact parent head `546716d6117918dbbb12a0720f7659b6a59ff002`.

## Contract

Both supported built-in producer forms remain green:

- `json.loads(review.to_json())`, with an exact built-in list of exact built-in check mappings;
- `review.as_dict()`, with the dataclass-preserved exact built-in tuple of exact built-in check mappings.

Equivalent-content subclasses must fail closed for the top-level mapping/schema keys, both supported check-container types, nested check mappings/schema keys, all revised lineage and review digests, reviewer provenance, fixed metadata, decision/check/result strings and the summary before normalization.

Rejection must leave caller-owned persisted input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #248 source. Persisted live validation (#458), reviewer producer/model canonicality, #244/#626 review-request work, direct-construction #252 and target-capable paths retain their ownership.

## Safety

Persistence-integrity acceptance only. No model invocation, target interaction, code/config application, tool/remediation/retest execution, deployment, verdict creation or attack-path mutation.

## Expected state

The exact #248 parser currently uses broad `isinstance`, schema equality, enum conversion, list/tuple and nested-dict checks, string/SHA helpers and summary `.strip()` normalization. The new tests are intentionally expected RED only for producer-impossible subclasses.
