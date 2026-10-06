# Implementation-plan review-request snapshot isolation

Issue: #303

## Purpose

The ST5 implementation-plan review request is immutable planning metadata. Its public serialization helpers must return detached snapshots so inspection or caller-side mutation cannot alter the canonical request or widen the review-request-only stop line.

This is a tests/docs-only sibling above the strict #280 persisted handoff. It changes no producer or parser behavior.

## Invariants

The dedicated regressions prove that:

- repeated `to_json()` output is byte-for-byte deterministic;
- untouched JSON and dictionary snapshots round-trip to the exact request;
- mutating top-level snapshot fields cannot change the source request or later JSON;
- independently returned snapshots do not alias;
- replacing, reordering, or truncating `required_checks` in a caller snapshot cannot affect the source and forged persisted forms fail closed;
- forged plan acceptance, action-authority flags, resolved future semantics, or a positive security verdict fail closed;
- after strict parsing, later mutation of the caller-owned persisted dictionary cannot mutate the parsed request.

## Stop line

`implementation_plan_review_requested=true` means only that independent review has been requested. It never implies plan acceptance or any code/tool/execution/target/retest/deploy/attack-path authority. Future semantics remain unresolved and the security verdict remains not evaluated.

## Collision boundary

This slice adds only:

- `tests/test_future_remediation_implementation_plan_review_request_snapshot_isolation.py`;
- `docs/future-remediation-implementation-plan-review-request-snapshot-isolation.md`.

It does not modify #278/#280-owned source/tests/docs, downstream #281/#283/#287 work, or the active #284 revision-request producer.

## Safety

All proof is in-memory persistence/integrity testing. There is no model invocation, network access, target interaction, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
