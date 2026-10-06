# Fresh-evidence coverage snapshot isolation

Issue: #313

## Purpose

The ST5 fresh-evidence coverage artifact reports whether each unresolved evidence gap currently has a live-valid fresh candidate admission. Even complete freshness coverage is not evidence sufficiency, gap closure, classification selection, transition resolution, or execution authority.

This tests/docs-only child proves that public serialization snapshots cannot mutate or widen the canonical typed coverage report.

## Persisted boundary

The strict #75/#77 parser consumes JSON-shaped lists and dictionaries, then reconstructs immutable typed coverage items and tuple-backed candidate evidence identities.

Producer-native `as_dict()` snapshots are detached inspection snapshots. This child does not broaden parser input semantics; canonical persistence is exercised through `to_json()` and JSON-derived dictionaries.

## Invariants

The dedicated regressions prove that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- canonical JSON and JSON-derived dictionaries restore the exact typed coverage report;
- top-level and nested item mutation in a producer `as_dict()` snapshot cannot mutate the source coverage or future JSON;
- independently returned snapshots do not alias nested item dictionaries or candidate-evidence tuple containers;
- caller-owned mutable persisted item/evidence lists are copied into typed immutable state, so later mutation cannot alter the parsed coverage;
- later top-level mutation of the caller-owned persisted dictionary cannot alter the parsed coverage;
- forged covered/missing counts or the all-gaps-covered flag fail closed;
- duplicate or malformed nested candidate evidence state fails closed;
- evidence sufficiency, gap closure, classification selection, transition creation and all action-authority flags remain false;
- forged future semantics or security verdict fail closed.

## Stop line

`all_gaps_have_fresh_candidates=true` means only that every unresolved gap currently has fresh candidate evidence. It does not establish that the evidence is sufficient, close a gap, select a classification, create a transition resolution, or authorize any target/action path.

All later sufficiency, classification, remediation, retest, deployment and verdict stages remain behind separate explicit boundaries.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_freshness_coverage_snapshot_isolation.py`;
- `docs/future-security-evidence-freshness-coverage-snapshot-isolation.md`.

It does not modify #73/#75/#77 source/tests/docs, admission/metadata-review/sufficiency siblings, #308/#309/#310/#311 snapshot work, or implementation-plan review files.

## Safety

All proof is offline/in-memory persistence integrity testing. No evidence collection, model invocation, network or target interaction, tool execution, classification selection, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation occurs.
