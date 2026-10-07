# ST5 revised implementation-plan schema key types

## Scope

This tests/docs-only acceptance slice is a child of strict revised
implementation-plan handoff #511.

- exact parent head: `f3948422929bb9d6525cb2df263c008c763de3f1`
- acceptance issue: #544
- production/source changes: **0**

It is separate from #521 sequence-container ownership, #514 live-validation
atomicity, #542/#543 fixed metadata values, #524 producer provenance,
#517/#519 revised-plan review-request work, scope authorization, and
target-capable code.

## Invariant

Every schema key in the programmatic persisted-dict path must be an exact
built-in string before set equality or field lookup.

#511 already requires exact built-in dictionaries for the top-level payload and
for each plan item. Their key schemas are still validated through set equality.
A `str` subclass carrying canonical key text inherits compatible
hashing/equality, so it passes that schema comparison and canonical field
lookup. JSON decoding cannot produce such polymorphic key objects.

The regression therefore covers the same exact-key invariant at both mapping
levels:

- canonical top-level and nested item keys remain accepted;
- a top-level string-key subclass fails closed;
- a nested plan-item string-key subclass fails closed;
- caller-owned mappings are not normalized or mutated as repair.

## Authority stop line

The revised implementation plan remains unaccepted planning text. This contract
authorizes no code/config change, tool call, execution, target interaction,
remediation, retest, deployment, attack-path mutation, future-state resolution,
or security verdict.

## Safety

The existing fixture uses only the in-memory model provider. No target
interaction, scanning, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation is introduced.
