# ST5 persisted implementation-plan revision-request metadata types

## Scope

This tests/docs-only acceptance slice is a child of strict implementation-plan
revision-request handoff #501.

- exact parent head: `81cd78f074a777a0380672050082fd21616a447c`
- acceptance issue: #538
- production/source changes: **0**

It is separate from #528/#529 direct typed-object metadata checks, #510 outer
mapping typing, #516 reviewer provenance, #522 SHA scalar typing, #536/#537
persisted sequence-container typing, #506 parser input-purity, #507
live-validation atomicity, #486 builder atomicity, and #534/#535 snapshot
isolation.

## Invariant

Fixed persisted metadata must use exact built-in strings before equality-based
validation.

The #501 parser currently compares these caller-owned values by equality:

- `schema_version`;
- `source_review_decision`;
- `future_semantics`;
- `security_verdict`.

A `str` subclass can retain noncanonical stored text while overriding
equality/inequality to report equality with the canonical constant. The parser
then constructs the typed request with canonical constants/defaults, silently
normalizing the persisted scalar instead of rejecting producer-impossible
state.

The regression requires canonical exact strings to remain accepted and all
polymorphic subclasses to fail closed before equality is consulted.

## Authority stop line

This contract grants no new workflow authority. The revision request remains
planning-only: no revised plan, code/config change, tool call, execution,
target interaction, remediation, retest, deployment, attack-path mutation,
future-state resolution, or security verdict is authorized.

## Safety

Pure in-memory persistence-integrity proof only. No model invocation, target
interaction, scanning, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
