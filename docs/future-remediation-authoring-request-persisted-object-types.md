# ST5 remediation authoring-request persisted object types

Issue: #628
Source owner: #198
Mode: tests/docs-only expected RED

## Contract

The strict remediation authoring-request handoff must reject polymorphic persisted object shapes before those objects can influence schema membership, iteration, equality, or typed-object construction.

The canonical JSON-decoded form remains supported: exact built-in `dict` mappings, exact built-in `list` containers, and exact built-in `str` schema keys.

The acceptance regression requires fail-closed handling for:

- a top-level `dict` subclass;
- a top-level schema-key `str` subclass;
- an `items` list subclass;
- an item mapping subclass and item schema-key subclass;
- list subclasses for `current_attack_path_ids`, `effect_ids`, and `capability_ids`;
- an evidence-list subclass;
- an evidence mapping subclass and evidence schema-key subclass.

Rejected caller-owned payloads must remain unchanged.

## Expected RED

The #198 parser currently admits mappings and list containers with `isinstance(..., dict/list)`, compares key sets by value, and validates string items with `isinstance(..., str)`. Equal-behaving subclasses can therefore cross the persisted-object boundary even though canonical producers emit built-ins.

This branch intentionally adds no production fix. #198 retains source ownership and can absorb the exact-type guards.

## Collision boundary

This slice does not overlap #583 raw JSON exact-`str`, existing authoring-request lineage/capability/evidence semantic branches, live-validation/purity branches, or the active #611-#627 persisted-object chain.

## Safety

Pure in-memory persistence-integrity acceptance. No model invocation, target interaction, scanning, remediation generation or execution, retest execution, deployment, scope authorization, verdict creation, or attack-path mutation.
