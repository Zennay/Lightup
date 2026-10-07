# Durable finding evidence-reference integrity

Issue: #851

## Boundary

`DomainStore.record_finding()` is the durable write boundary for product
findings. It is lower-level than the lab-sync bridge and can be called by other
producers, so evidence-reference integrity must not depend solely on
`persist_lab_findings()`.

A durable Finding → Impact → Fix → Retest record must carry canonical,
non-empty evidence lineage.

## Current gap

The write path currently constructs the record with:

```python
evidence_ids=tuple(evidence_ids)
```

That normalizes arbitrary iterables instead of validating the typed boundary.
As a result the write path currently accepts:

- an empty evidence tuple;
- a bare string, split into one-character references;
- mutable lists and tuple subclasses;
- string subclasses;
- blank references;
- duplicate references.

Some of these shapes are normalized again by JSON persistence/readback, hiding
the non-canonical caller input after the durable write.

## Acceptance contract

Before the finding INSERT:

- `evidence_ids` is an exact built-in `tuple`;
- the tuple is non-empty;
- every entry is an exact built-in `str`;
- every reference is non-blank;
- references are unique;
- malformed input raises `ValueError`;
- rejection leaves the durable findings table unchanged;
- canonical readback preserves the original evidence-reference sequence.

## Layering

This is a defense-in-depth durable persistence contract.

- #848 owns canonical finding-local evidence shape at `persist_lab_findings()`;
- #850 owns evidence presence at that same bridge;
- #849 owns polymorphic `FindingRecord` admission during lab retest;
- #851 owns the lower-level write boundary used by any producer.

## Collision boundary

Active PR #828 already modifies `src/lightup/domain.py` for finding-read
tenant-lineage enforcement. To avoid taking that worker's file ownership, this
branch is tests/docs only and does not edit `domain.py`.

A later source-owner can absorb the write-side evidence validation after or
alongside the active domain lineage work.

## Safety

Temporary-SQLite durable-data integrity proof only. No DNS/network access,
target interaction, evidence collection, capability execution,
remediation/retest execution, deployment, security verdict creation or
attack-path mutation.
