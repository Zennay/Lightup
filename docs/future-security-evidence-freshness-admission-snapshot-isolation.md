# Freshness-admission snapshot isolation

Issue: #316

## Purpose

The ST5 freshness admission proves only that newly supplied candidate evidence is genuinely fresh relative to the unresolved gap constraints. Freshness does not evaluate evidence suitability, select a classification, create a transition resolution, or authorize collection, tools, targets, execution, remediation, retest, deployment, or attack-path mutation.

This tests/docs-only child proves that serialization snapshots cannot mutate or widen the canonical typed admission.

## Persisted boundary

The strict #70/#72 handoff consumes JSON-shaped candidate-evidence dictionaries and candidate ID/capability lists, then reconstructs immutable typed fingerprints and tuple-backed identities.

Producer-native `as_dict()` snapshots are detached inspection snapshots. This child does not broaden parser input semantics; canonical persistence is exercised through `to_json()` and JSON-derived dictionaries.

## Invariants

The dedicated regressions prove that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- canonical JSON and JSON-derived dictionaries restore the exact typed admission;
- top-level, fingerprint and collection replacement in a producer `as_dict()` snapshot cannot mutate the source admission or future JSON;
- independently returned producer snapshots do not alias nested fingerprint dictionaries or candidate identity collections;
- caller-owned mutable candidate-evidence dictionaries/lists are copied during strict parsing, so later caller mutation cannot alter the parsed admission;
- later top-level mutation of the caller-owned persisted dictionary cannot alter the parsed admission;
- fingerprint run drift, digest drift and duplicate candidate evidence fail closed;
- `freshness_check_passed` cannot be forged false while retaining a valid admission;
- evidence suitability, classification selection, transition creation and every action-authority flag remain false;
- forged future semantics or security verdict fail closed.

## Stop line

A valid freshness admission means only that fresh candidate evidence exists and is bound to the exact candidate run and evidence fingerprints. It does not assert that the evidence is suitable or sufficient and does not select or accept any security outcome.

All later metadata review, sufficiency, classification, remediation, retest, deployment and verdict stages remain behind separate explicit boundaries.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_freshness_admission_snapshot_isolation.py`;
- `docs/future-security-evidence-freshness-admission-snapshot-isolation.md`.

It does not modify #69/#70/#72 source/tests/docs, coverage/metadata/sufficiency siblings, #308/#309/#310/#311/#313 snapshot work, or implementation-plan review files.

## Safety

All proof is offline/in-memory persistence integrity testing. No evidence collection, model invocation, network or target interaction, tool execution, classification selection, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation occurs.
