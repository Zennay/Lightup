# Evidence-collection request snapshot isolation

Issue: #318

## Purpose

The ST5 evidence-collection request is planning metadata for unresolved evidence gaps. It states that fresh evidence and a fresh run are required, but it does not authorize evidence collection, choose a capability, create a tool call, interact with a target, authorize remediation/retest/deployment, or select a security outcome.

This tests/docs-only child proves that public serialization snapshots cannot mutate or widen the canonical typed request.

## Persisted boundary

The strict #63/#64 handoff consumes JSON-shaped item dictionaries and lineage lists, then reconstructs immutable typed request items and tuple-backed lineage collections.

Producer-native `as_dict()` snapshots are detached inspection snapshots. Canonical persisted input remains JSON/JSON-derived dictionaries; this child does not widen parser input semantics.

## Invariants

The dedicated regressions prove that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- canonical JSON and JSON-derived dictionaries restore the exact typed request;
- top-level and nested item mutation in a producer `as_dict()` snapshot cannot mutate the source request or future JSON;
- independently returned snapshots do not alias nested item dictionaries;
- caller-owned mutable effect/path/evidence/capability lists are copied during strict parsing, so later mutation cannot alter the parsed request;
- later top-level mutation of the caller-owned persisted dictionary cannot alter the parsed request;
- forged gap counts and top-level collection/tool/target/execution/remediation/retest/deployment/attack-path authority fail closed;
- forged classification, graph action, freshness requirement, remediation authorization, or duplicate provenance fails closed;
- forged future semantics or security verdict fail closed.

## Stop line

`fresh_evidence_required=true` and `fresh_run_required=true` are requirements for a later collection stage only. They do not authorize collection and do not select a capability, tool, target, argument, credential, remediation, retest, deployment, classification, or verdict.

Every later action remains behind a separate explicit authority boundary.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_collection_request_snapshot_isolation.py`;
- `docs/future-security-evidence-collection-request-snapshot-isolation.md`.

It does not modify #61/#63/#64 producer or strict-handoff source/tests/docs, freshness/admission/coverage/metadata/sufficiency siblings, current snapshot siblings, or implementation-plan review files.

## Safety

All proof is offline/in-memory persistence-integrity testing. No evidence collection, model invocation, network or target interaction, tool execution, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation occurs.
