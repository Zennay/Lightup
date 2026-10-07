# ST5 revised-remediation review persisted-integrity pack

Issue #679 composes four already-isolated acceptance contracts above strict revised-remediation review handoff #248.

## Pinned parent

`546716d6117918dbbb12a0720f7659b6a59ff002` — exact #248 head.

## Included acceptance slices

- #591: raw persisted JSON must be an exact built-in `str`.
- #627: persisted mappings, schema keys, sequence containers, nested mappings and scalar strings must preserve exact built-in runtime types.
- #630: direct persisted-object parsing is deterministic and does not mutate caller-owned input on success or fail-closed rejection.
- #629: `as_dict()`/`to_json()` snapshots are detached and cannot mutate the immutable typed review after parsing.

All component tests and documents are copied byte-for-byte from their dedicated branch heads. This pack adds no production/source files.

## Expected result

The snapshot/purity controls are intended GREEN on the pinned #248 head. The raw-JSON and persisted-object exactness contracts remain intentionally RED until the #248 source owner absorbs exact-type guards. A full-suite non-green result must therefore be interpreted against those explicit expected-RED cases rather than as authority to modify source from this pack.

## Collision boundary

Composition only. Do not edit `src/lightup/**` from this branch. #248 retains strict persisted-review source ownership; #458 retains live-validation atomicity; reviewer producer/model lanes, #250 whole-loop invariants, #252 direct construction, scope authorization and target-capable paths remain separate.

## Safety

Persistence-integrity validation only. No model/network call, target interaction, scanning, code/config application, tool/remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.