# ST5 revised-plan producer input/state atomicity

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It proves producer read-only behavior. It is separate from #484 revision-request builder atomicity and #514 strict revised-plan handoff/live-validation atomicity. It does not modify #503 source or any parser, provenance, scope-authorization, or target-capable path.

## Invariant

Revised-plan generation may read strict persisted lineage and live evidence state, and it may invoke the configured in-memory model provider. It must not mutate caller-owned persisted structures or live orchestration state.

On canonical success:
- caller-owned persisted dictionaries remain unchanged;
- `runs`, `capability_leases`, and `evidence` rows remain value-identical;
- run creation, lease acquisition, and evidence insertion are forbidden;
- repeated generation is deterministic.

On deliberate live evidence SHA drift:
- rejection occurs before model invocation;
- repeated rejection is deterministic;
- caller-owned persisted dictionaries remain unchanged;
- the already-drifted live state remains unchanged;
- no write API is invoked.

## Safety

The proof uses only deterministic in-memory model fixtures and temporary SQLite state. No external model/network call, target interaction, scanning, execution, remediation/retest action, deployment, security verdict, or attack-path mutation occurs.
