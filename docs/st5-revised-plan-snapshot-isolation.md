# ST5 revised implementation-plan snapshot isolation

## Scope

This tests/docs-only acceptance slice is a child of strict revised
implementation-plan handoff #511.

- exact parent head: `f3948422929bb9d6525cb2df263c008c763de3f1`
- acceptance issue: #546
- production/source changes: **0**

It is separate from #521 sequence-container ownership, #514 live validation,
#542/#543 fixed metadata types, #544/#545 schema-key types, #524 producer
provenance, #517/#519 revised-plan review-request work, scope authorization and
target-capable code.

## Invariant

Public serialization must behave as a detached snapshot boundary around the
canonical unaccepted revised implementation plan.

The regression proves that:

- repeated `to_json()` output is byte-for-byte deterministic;
- canonical untouched dict and JSON snapshots round-trip exactly;
- separately returned `as_dict()` values do not alias their nested
  plan-item mappings;
- mutating top-level or nested caller-owned snapshot data cannot change the
  typed source artifact or later serialization;
- forged snapshots cannot claim plan acceptance, execution authority, resolved
  future semantics, or a security verdict;
- mutating nested caller-owned persisted data after successful parsing cannot
  mutate the already parsed typed plan.

## Authority stop line

Snapshot creation and strict parsing remain persistence/integrity operations.
The revised plan remains unaccepted and authorizes no code/config change, tool
call, execution, target interaction, remediation, retest, deployment,
attack-path mutation, future-state resolution, or security verdict.

## Safety

The existing fixture uses only the in-memory model provider. No target
interaction, scanning, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation is introduced.
