# ST5 implementation-plan persisted object-shape exactness

Issue: #601  
Parent: #237 exact head `f8da50cae174d372be20ccef4a203a766db63618`

## Purpose

The strict persisted implementation-plan parser supports both direct Python
objects and raw JSON. JSON decoding can only produce exact built-in mappings,
string keys, lists and strings. Direct callers can currently widen that shape
with subclasses that the parser accepts through `isinstance`, set equality,
membership or string normalization.

## Required contract

Both canonical producer forms remain valid:

- `plan.as_dict()`, whose sequence fields are exact tuples;
- `json.loads(plan.to_json())`, whose sequence fields are exact lists.

The direct parser must reject polymorphic subclasses at these boundaries before
normalization:

- top-level mapping;
- every top-level schema key;
- `plan_items` list/tuple container;
- each nested plan-item mapping and each nested schema key;
- `assumptions` and `unresolved_questions` list/tuple containers;
- top-level persisted strings: schema, lineage/digests, model provenance,
  summary and fixed future/verdict metadata;
- nested plan-item strings including `change_area`;
- persisted assumption strings.

Caller-owned input must remain unchanged on rejection.

## Current expected RED

At #237 head `f8da50cae174d372be20ccef4a203a766db63618`:

- mappings use `isinstance(..., dict)`;
- schemas rely on `set(mapping) == EXPECTED_KEYS`;
- sequence fields use `isinstance(..., (list, tuple))`;
- bounded/digest strings use `isinstance(..., str)`, while fixed values rely
  on equality/membership;
- bounded text calls `.strip()`, which can normalize an accepted subclass.

## Collision boundary

#595 owns raw JSON text exactness. #358, #360 and #361 own parser, live-validator
and composed-chain atomicity. Existing nested duplicate-key JSON and snapshot
isolation work remain separate. This branch changes tests/docs only and does
not modify #237 source, model calls, scope authorization or target-capable
behavior.

## Safety

Persisted planning-artifact integrity only. Test fixtures use the existing
in-memory provider. No target interaction, remediation/retest execution,
deployment, verdict creation or attack-path mutation.
