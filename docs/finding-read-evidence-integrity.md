# Finding read evidence integrity

Issue #856 isolates the persisted read-side evidence-lineage boundary for `FindingRecord`.

## Boundary

`DomainStore.record_finding()` serializes evidence references to `findings.evidence_ids_json`, and `DomainStore._finding_from_row()` currently reconstructs them with:

```python
evidence_ids=tuple(json.loads(row["evidence_ids_json"]))
```

That expression validates neither the decoded container nor its members. A legacy or corrupted durable row can therefore be normalized into a typed `FindingRecord` even when its evidence lineage was never a canonical JSON array of evidence-reference strings.

Examples include:

- a JSON string becoming one-character references;
- a JSON object becoming key references;
- array elements that are numbers, booleans, objects or null;
- blank evidence references;
- duplicate evidence references.

The durable read boundary must reject these forms before a `FindingRecord` escapes.

## Acceptance contract

The dedicated acceptance module proves:

1. a canonical JSON array of non-blank evidence-reference strings remains readable and preserves order;
2. an empty JSON array remains readable because manual findings may legitimately carry no evidence;
3. the decoded top-level value must be an exact built-in list;
4. every member must be an exact non-blank built-in string;
5. evidence references must be unique;
6. malformed persisted evidence raises a deterministic evidence-integrity `ValueError`;
7. rejection is read-only and leaves the durable `evidence_ids_json` bytes unchanged.

## Ownership and composition

This branch is pinned above PR #828 exact head `f9ee5b9cc5abd84aa85f398f0859678cd722266b` so its tenant-lineage read filtering remains part of the acceptance ancestry.

This slice intentionally changes **no production source**:

- PR #828 retains active `src/lightup/domain.py` finding-read query ownership;
- #851 retains the independent write-side `record_finding(..., evidence_ids=...)` contract;
- PR #184 / PR #854 / #849 retain lab synchronization and retest ownership.

A later source successor should add a narrow persisted-evidence decoder/validator before `FindingRecord` construction, without broadening tenant visibility or mutating corrupt rows.

## Expected RED

On the pinned source head, malformed JSON values such as a string, object, non-string array item, blank string or duplicate references can currently be normalized and returned. The new regressions are therefore expected to fail until the read-side validator is absorbed by the `domain.py` source owner.

## Safety

This is temporary-SQLite persisted-data integrity testing only. It performs no network or target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
