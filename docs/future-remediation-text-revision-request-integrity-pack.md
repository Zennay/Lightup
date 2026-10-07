# ST5 remediation-text revision-request persisted-integrity pack

Issue #687 composes four isolated acceptance contracts above strict remediation-text revision-request handoff #231.

## Pinned parent

`30ebbd9f335bcbbc0ab076d344b79d94be8434e6` — exact #231 head.

## Included slices

- #587: raw persisted JSON must be an exact built-in `str`.
- #624: persisted mappings, schema keys, sequence containers and scalar strings preserve exact built-in runtime types.
- #644: direct persisted-object parsing preserves caller-owned input on success and deterministic rejection.
- #634: public serialization snapshots are detached and cannot mutate the typed revision request after parsing.

All component files are copied byte-for-byte from their dedicated acceptance branches. This pack adds no production/source files.

## Expected result

Purity/snapshot controls are intended GREEN. Raw-JSON/object exactness remain intentionally RED until #231 absorbs exact-type guards. This pack does not own the source repair.

## Collision boundary

Composition only. Do not edit `src/lightup/**` from this branch. #231 retains handoff source ownership; #460 live-validation atomicity, #463 builder atomicity, #220 prior review, #238 downstream proposal, model/gateway, scope authorization and target-capable lanes remain separate.

## Safety

Persistence-integrity validation only. No model/network call, target interaction, scanning, execution, remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.