# ST5 revised-remediation review-request persisted-integrity pack

Issue #681 composes four isolated acceptance contracts above strict revised-remediation review-request handoff #244.

## Pinned parent

`7eb4f5f72f5656b5476ba8735d7e83ded06decf3` — exact #244 head.

## Included slices

- #589: raw persisted JSON must be an exact built-in `str`.
- #626: persisted mappings, schema keys, sequence containers and scalar values preserve exact built-in runtime types.
- #631: direct persisted-object parsing preserves caller-owned input on success and deterministic rejection.
- #632: public serialization snapshots are detached and cannot mutate the typed request after parsing.

All component files are copied byte-for-byte from their dedicated acceptance branches. This pack adds no production/source files.

## Expected result

Snapshot/purity controls are intended GREEN. Raw-JSON and persisted-object exactness remain intentionally RED until #244 absorbs exact-type guards. The pack itself does not own that source change.

## Collision boundary

Composition only. Do not edit `src/lightup/**` from this branch. #244 keeps handoff source ownership; #461 live-validation atomicity, #464 builder atomicity, #248 downstream review, model/gateway, scope authorization and target-capable lanes remain separate.

## Safety

Persistence-integrity validation only. No model/network call, target interaction, scanning, execution, remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.