# Evidence metadata-review snapshot isolation

Issue: #311

## Purpose

The ST5 evidence metadata-contract review proves only that the admitted candidate evidence carries one internally consistent existing metadata contract. It does not prove evidence sufficiency, select a classification, create a transition resolution, or grant collection, tool, target, execution, remediation, retest, deployment, or attack-path authority.

This tests/docs-only child proves that public serialization snapshots cannot mutate or widen the canonical typed review.

## Persisted boundary

The strict #79 handoff accepts persisted JSON list shapes for `candidate_evidence_ids` and `candidate_capability_ids`, then converts them into immutable tuples on the typed review.

Producer-native `as_dict()` snapshots remain detached inspection snapshots. This child does not widen the persisted parser to accept tuple containers directly; canonical persistence is exercised through `to_json()` and JSON-derived dictionaries.

## Invariants

The dedicated regressions prove that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- canonical JSON and JSON-derived dictionary forms restore the exact typed review;
- top-level and collection replacement in a producer `as_dict()` snapshot cannot mutate the source review or future JSON;
- independently returned producer snapshots do not alias candidate-ID tuple containers;
- caller-owned mutable candidate evidence/capability lists are copied during strict parsing, so later list mutation cannot alter the parsed review;
- later top-level mutation of the caller-owned persisted dictionary cannot alter the parsed review;
- forged metadata-contract verification or freshness state fails closed;
- evidence sufficiency, classification selection, transition creation and all action-authority flags remain false;
- forged future semantics, security verdict, or classification claim fails closed.

## Stop line

`metadata_contract_verified=true` and `freshness_check_passed=true` are evidence-integrity facts only. They do not imply that the evidence is sufficient and do not select or accept a security classification.

Any sufficiency decision, classification selection, transition resolution, execution, target interaction, remediation, retest, deployment, or verdict remains behind a separate explicit boundary.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_metadata_contract_review_snapshot_isolation.py`;
- `docs/future-security-evidence-metadata-contract-review-snapshot-isolation.md`.

It does not modify #76/#79/#81 producer or strict-handoff source/tests/docs, #82/#83 downstream sufficiency-request work, #308/#309/#310 snapshot siblings, or implementation-plan review files.

## Safety

All proof is offline/in-memory persistence integrity testing. No evidence collection, model invocation, network or target interaction, tool execution, classification selection, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation occurs.
