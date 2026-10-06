# Implementation-plan review snapshot isolation

Issue: #298

## Purpose

The persisted ST5 implementation-plan review is a planning/review artifact, not an action-authority object. Its public serialization helpers therefore have to behave as detached snapshots: callers may inspect or mutate returned dictionaries without changing the canonical review that produced them.

This contract is intentionally layered above the strict review handoff and the #287 non-execution chain invariant. It adds no producer behavior and changes no existing source.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- untouched JSON and dictionary forms still round-trip through the strict parser to the exact review;
- top-level mutation of an `as_dict()` snapshot cannot change the source review or its later JSON;
- nested review-check mutation cannot change the source review;
- independently returned snapshots do not alias at the top level or inside nested check dictionaries;
- forged snapshot claims for code/tool/execution/target/retest/deploy/attack-path authority fail closed;
- forged resolved future semantics, a positive security verdict, review acceptance drift, or check/decision drift fail closed;
- after strict parsing, later mutation of the caller-owned persisted dictionary cannot mutate the parsed review.

## Security boundary

Snapshot isolation is not authorization. An approved implementation-plan review may retain only the existing `implementation_plan_accepted=true` planning marker. Every action-authority field remains exact false, `future_semantics` remains `unresolved`, and `security_verdict` remains `not_evaluated`.

Any later code generation, tool invocation, target interaction, retest, deployment, future-state resolution, or attack-path mutation still requires a separate explicit boundary.

## Collision boundary

This slice adds only:

- `tests/test_future_remediation_implementation_plan_review_snapshot_isolation.py`;
- `docs/future-remediation-implementation-plan-review-snapshot-isolation.md`.

It does not modify #278/#280/#281/#283/#287-owned code/tests/docs and does not touch #284 revision-request work.

## Safety

All proof is in-memory persistence/integrity testing. There is no external model call, network access, target interaction, remediation execution, retest, deployment, verdict creation, or attack-path mutation.
