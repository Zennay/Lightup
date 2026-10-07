# ST5 remediation-text revision-request persisted object type exactness

Issue #624 isolates persisted-object type fidelity above strict remediation-text revision-request handoff #231 at exact parent head `30ebbd9f335bcbbc0ab076d344b79d94be8434e6`.

## Contract

Two built-in producer forms are already part of this handoff's supported contract and must remain green:

- `json.loads(request.to_json())`, where `revision_checks` is an exact built-in list;
- `request.as_dict()`, where the dataclass preserves `revision_checks` as an exact built-in tuple.

The direct parser must reject equivalent-content Python subclasses at the persistence boundary instead of silently accepting or normalizing them. The acceptance pack covers the top-level mapping and schema keys, lineage/request SHA-256 strings, schema/future/verdict metadata, the fixed `review_decision`, both supported revision-check container types, and each revision-check string.

Rejection must leave caller-owned input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch adds tests/docs only and does not modify #231 source. #463 retains builder atomicity, #460 retains persisted live-validation atomicity, raw JSON typing stays separate, #623 owns the prior review handoff, and #234/#238 plus revised-review stages keep their current scopes.

## Safety

Persistence-integrity acceptance only. No model call, target interaction, code/config generation or application, tool/remediation/retest execution, deployment, security verdict, or attack-path mutation.

## Expected state

The exact #231 parser currently uses broad `isinstance`, schema/value equality, SHA helpers and sequence coercion. The new tests are intentionally expected RED only for producer-impossible subclass values; both exact built-in supported forms remain green.
