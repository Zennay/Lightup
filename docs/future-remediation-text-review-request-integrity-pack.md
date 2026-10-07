# ST5 remediation-text review-request persisted-integrity pack

Issue #691 composes four isolated acceptance contracts above the current strict remediation-text review-request handoff #215.

## Pinned parent

`cee2e5391f32eed5212424d778c66cae73042e4a` — current exact #215 head.

## Included slices

- #585: raw persisted JSON must be an exact built-in `str`.
- #622: persisted mappings, schema keys, sequence containers and scalar values preserve exact built-in runtime types.
- #642: direct persisted-object parsing preserves caller-owned input on success and deterministic rejection.
- #635: public serialization snapshots are detached and cannot mutate the typed review request after parsing.

## #585 carry-forward

#585 was authored one #215 parent commit earlier. The intervening source change only added tuple support for `required_checks`; the current raw JSON entry point still uses broad `isinstance(raw, str)` before `strip()`/decode. The #585 test/doc are copied unchanged here so the current-head pack preserves that contract without modifying the #585 branch.

All component files are copied byte-for-byte from their dedicated acceptance branches. This pack adds no production/source files.

## Expected result

Purity/snapshot controls are intended GREEN. Raw-JSON/object exactness remain expected RED where #215 still admits producer-impossible runtime subclasses. This pack does not own source repair.

## Collision boundary

Composition only. Do not edit `src/lightup/**` from this branch. #215 retains handoff source ownership; #459 live-validation atomicity, #462 builder atomicity, #209 upstream proposal, #220 downstream review, model/gateway, scope authorization and target-capable lanes remain separate.

## Safety

Persistence-integrity validation only. No model/network call, target interaction, scanning, execution, remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.