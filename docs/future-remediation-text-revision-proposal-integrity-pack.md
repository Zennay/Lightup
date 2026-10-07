# ST5 remediation-text revision-proposal persisted-integrity pack

Issue #684 composes four isolated acceptance contracts above strict remediation-text revision-proposal handoff #238.

## Pinned parent

`ef38622caf8c63be34785f971d0526e85740b55d` — exact #238 head.

## Included slices

- #588: raw persisted JSON must be an exact built-in `str`.
- #625: persisted mappings, schema keys and scalar strings preserve exact built-in runtime types.
- #645: direct persisted-object parsing preserves caller-owned input on success and deterministic rejection.
- #633: public serialization snapshots are detached and cannot mutate the typed revised proposal after parsing.

All component files are copied byte-for-byte from their dedicated acceptance branches. This pack adds no production/source files.

## Expected result

Purity/snapshot controls are intended GREEN. Raw-JSON/object exactness remain intentionally RED until #238 absorbs exact-type guards. This pack does not own the source repair.

## Collision boundary

Composition only. Do not edit `src/lightup/**` from this branch. #238 retains handoff source ownership; #456 live-validation atomicity, #468 producer atomicity, #231 upstream revision-request, #244 downstream review-request, model/gateway, scope authorization and target-capable lanes remain separate.

## Safety

Persistence-integrity validation only. No model/network call, target interaction, scanning, execution, remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.