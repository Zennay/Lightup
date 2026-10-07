# ST5 revised implementation-plan persisted metadata types

## Scope

This tests/docs-only acceptance slice is a child of strict revised
implementation-plan handoff #511.

- exact parent head: `f3948422929bb9d6525cb2df263c008c763de3f1`
- acceptance issue: #542
- production/source changes: **0**

It is separate from #521 nested sequence-container hardening, #514 live
validation atomicity, #524 producer provenance, #517/#519 revised-plan
review-request ownership, #526/#527 review-request metadata typing, scope
authorization, and target-capable code.

## Invariant

Fixed persisted revised-plan metadata must use exact built-in strings before
equality validation.

#511 already validates SHA lineage, provider/model provenance, summary and plan
text with exact string typing. Three fixed fields still rely on value equality:

- `schema_version`;
- `future_semantics`;
- `security_verdict`.

A `str` subclass can retain noncanonical stored text while overriding
equality/inequality to appear canonical. The parser then constructs the typed
revised plan with canonical constants/defaults, silently normalizing persisted
state that the producer cannot emit.

The regression requires canonical exact strings to remain accepted and each
polymorphic subclass to fail closed before equality is consulted.

## Authority stop line

The revised plan remains unaccepted planning text. This contract authorizes no
code/config change, tool call, execution, target interaction, remediation,
retest, deployment, attack-path mutation, future-state resolution, or security
verdict.

## Safety

The existing fixture uses only the in-memory model provider. No target
interaction, scanning, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation is introduced.
