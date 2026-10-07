# ST5 remediation-text proposal persisted-integrity pack

Issue #689 composes four isolated acceptance contracts above strict remediation-text proposal handoff #209.

## Pinned parent

`38c40d112751728c238dcf5d7ab556079528c38e` — exact #209 head.

## Included slices

- #584: raw persisted JSON must be an exact built-in `str`.
- #621: persisted mappings, schema keys and scalar strings preserve exact built-in runtime types.
- #641: direct persisted-object parsing preserves caller-owned input on success and deterministic rejection.
- #636: public serialization snapshots are detached and cannot mutate the typed proposal after parsing.

All component files are copied byte-for-byte from their dedicated acceptance branches. This pack adds no production/source files.

## Expected result

Purity/snapshot controls are intended GREEN. Raw-JSON/object exactness remain expected RED where #209 still admits producer-impossible subclasses. This pack does not own source repair.

## Collision boundary

Composition only. Do not edit `src/lightup/**` from this branch. #209 retains handoff source ownership; proposal producer/live-validation atomicity owners, #198 upstream authoring request, #215 downstream review-request, model/gateway, scope authorization and target-capable lanes remain separate.

## Safety

Persistence-integrity validation only. No external model/network call, evidence collection, target interaction, scanning, execution, remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.