# Fresh-evidence coverage snapshot isolation

Issue: #314

## Purpose

ST5 fresh-evidence coverage reports which unresolved evidence gaps currently have a live-valid fresh candidate admission. Coverage is not evidence sufficiency, gap closure, a selected classification, a transition resolution, or action authority.

Because the persisted artifact contains nested coverage items and candidate-evidence collections, both top-level and nested serialization snapshots must be detached from canonical typed state.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic for both covered and uncovered reports;
- untouched JSON round-trips through the strict #75 parser to the exact coverage artifact;
- mutating top-level or nested `as_dict()` snapshots cannot mutate the source coverage or later JSON;
- independently returned snapshots do not alias the outer item tuple, nested item dictionaries, or candidate-evidence tuples;
- JSON-decoded caller-owned outer item lists, nested item dictionaries, and candidate-evidence lists are copied into immutable typed state during parsing;
- later mutation of any of those caller-owned containers cannot mutate a parsed covered or uncovered report;
- covered/uncovered identity semantics, derived counts, and the all-covered flag remain exact;
- evidence sufficiency, gap closure, classification selection, transition creation and every action-authority field remain false;
- future semantics remain unresolved and the security verdict remains not evaluated.

## Stop line

`all_gaps_have_fresh_candidates=true` means freshness coverage only. It never means the evidence is sufficient and never closes a security gap.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_freshness_coverage_snapshot_isolation.py`;
- `docs/future-security-evidence-freshness-coverage-snapshot-isolation.md`.

It does not modify the coverage producer/parser or existing coverage tests/docs, and it does not modify the active coverage consumer or later metadata/sufficiency branches.

## Safety

All proof is in-memory persistence/integrity testing. There is no evidence collection, sufficiency decision, target interaction, classification selection, remediation/retest execution, deployment, or attack-path mutation.
