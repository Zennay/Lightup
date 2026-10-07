# ST5 remediation/retest persisted-type extension pack

Issue #694 composes only the newer runtime-type acceptance slices added after the existing full #190 handoff-integrity pack.

## Pinned parent

`c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13` — exact #190 head.

## Included slices

- #609: raw persisted JSON requires an exact built-in `str`.
- #620: direct persisted objects require exact built-in mappings, keys, sequence containers and scalar runtime types.

## Existing proof deliberately not duplicated

`chatgpt/st5-remediation-retest-full-handoff-integrity-pack-20261006` already consolidates parser/live/snapshot integrity and has permanent VPS-green proof. This extension only carries the later exact-type additions.

All four component files are copied byte-for-byte from their dedicated acceptance branches. This extension adds no production/source files.

## Expected result

These are expected-RED type-narrowing contracts until the #190 source owner absorbs exact built-in type guards. This branch does not own that source repair.

## Safety

Persistence-integrity validation only. No target interaction, evidence collection, capability/tool selection, remediation/retest execution, deployment, verdict creation or attack-path mutation.