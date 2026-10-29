# Lab finding evidence-reference integrity

Issue: #848

## Boundary

`persist_lab_findings()` is the bridge that turns isolated-lab assessment
output into durable product findings. Those findings feed the
Finding → Impact → Fix → Retest workflow, so the evidence references attached
at this boundary must preserve the canonical producer shape.

The planner-driven lab producer emits finding-local evidence references as an
exact built-in JSON-style list of exact strings. The older single-lane
`run_lab_baseline()` producer carries one exact top-level `evidence_id`
string instead.

The bridge must reject malformed caller-owned shapes instead of normalizing
them into different durable evidence lineage.

## Current gap

The current finding-local conversion is:

```python
tuple(finding.get("evidence_ids", ()))
```

That treats arbitrary iterables as evidence collections. A string such as
`"evidence:abc"` is therefore persisted as one-character references. List
subclasses, string subclasses, blank references and duplicates are likewise
normalized or retained even though the canonical producer does not emit those
forms.

The fallback path also accepts a non-string or blank top-level
`evidence_id` and persists it inside the typed `FindingRecord.evidence_ids`
tuple.

## Acceptance contract

Before calling `DomainStore.record_finding()`:

- when a finding-local `evidence_ids` key is present, its value is an exact
  built-in `list`;
- every list entry is an exact built-in `str`;
- every reference is non-blank without normalization;
- references are unique;
- malformed input raises `ValueError` and no finding row is written;
- when no finding-local evidence list is present, the legacy top-level
  `evidence_id` fallback remains accepted only as an exact non-blank built-in
  string;
- canonical planner-driven and single-lane shapes keep their existing durable
  tuple representation.

This contract validates reference metadata only. It does not read raw evidence
payloads and does not claim that a reference exists in a separate ledger.

## Expected state

Expected RED on exact PR #184 head
`bc7242d5171856f69f2ec68d7b3cf06d64bbb938`.

The source owner can absorb a narrow validation helper in
`src/lightup/labsync.py` before `record_finding()`; this sidecar does not
change production source.

## Collision boundary

PR #184 retains all `labsync.py` source ownership and durable internal-lab
provenance behavior.

This branch adds only:

- `tests/test_labsync_finding_evidence_reference_integrity.py`;
- this contract document.

It does not modify domain/state schema, review-pipeline work
(#840/#842/#845/#847), retest observation, scope authorization, capability
workers, deployment, verdict or attack-path code.

## Safety

Temporary-SQLite, offline persistence-integrity proof only. No DNS/network
access, target interaction, evidence collection, capability execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation.
