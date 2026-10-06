# Evidence-sufficiency attestation snapshot isolation

Issue: #308

## Purpose

The ST5 evidence-sufficiency attestation records an operator's bounded evidence-sufficiency disposition. It still does not select a LightUp security classification, create a transition resolution, or grant collection, tool, target, execution, remediation, retest, deployment, or attack-path authority.

This tests/docs-only child proves that serialization snapshots cannot mutate or widen the canonical typed attestation.

## Persisted boundary

The strict #93 handoff accepts persisted JSON list shapes for `candidate_evidence_ids` and `candidate_capability_ids`, then converts them into immutable tuples on the typed attestation.

Producer-native `as_dict()` snapshots are useful detached inspection snapshots, but this child does not widen the persisted handoff to accept tuple containers directly. Canonical persistence is exercised through `to_json()` and JSON-derived dictionaries.

## Invariants

The dedicated regressions prove that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- canonical JSON and JSON-derived dictionary forms restore the exact typed attestation;
- top-level and collection replacement in a producer `as_dict()` snapshot cannot mutate the source attestation or future JSON;
- separately returned producer snapshots do not alias their candidate-ID tuple containers;
- caller-owned mutable candidate evidence/capability lists are copied during strict parsing, so later list mutation cannot alter the parsed attestation;
- later top-level mutation of the caller-owned persisted dictionary cannot alter the parsed attestation;
- forged derived sufficiency/justification/eligibility flags fail closed;
- classification-selection, resolution, collection/tool/execution/target/remediation/retest/deployment/attack-path authority remains false;
- forged future semantics, security verdict, classification claim, or disposition fail closed.

## Stop line

Even the `sufficient_claim_justified` disposition means only that a later classification-review stage may be considered. It does not select the classification and does not resolve future state.

Any classification selection, transition resolution, execution, target interaction, remediation, retest, deployment, or verdict remains behind a separate explicit boundary.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_sufficiency_attestation_snapshot_isolation.py`;
- `docs/future-security-evidence-sufficiency-attestation-snapshot-isolation.md`.

It does not modify #90/#92/#93 producer or strict-handoff source/tests/docs, #95 downstream classification-review work, #305/#306 schema-erosion work, or implementation-plan review files.

## Safety

All proof is offline/in-memory persistence integrity testing. No model invocation, evidence collection, network or target interaction, tool execution, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation occurs.
