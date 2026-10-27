# Durable finding evidence-reference integrity

Issue: #851

## Boundary

`DomainStore.record_finding()` is the durable write boundary for product
findings. It is lower-level than the lab-sync bridge and can be called by other
producers, so evidence-reference integrity must not depend solely on
`persist_lab_findings()`.

Manual/domain findings may intentionally carry no evidence references. When a
finding does carry evidence, that lineage must be canonical and must not be
silently normalized from a producer-impossible caller shape.

## Current gap

The write path currently constructs the record with:

```python
evidence_ids=tuple(evidence_ids)
```

That normalizes arbitrary iterables instead of validating the typed boundary.
As a result the write path currently accepts:

- a bare string, split into one-character references;
- mutable lists and tuple subclasses;
- string subclasses;
- blank references;
- duplicate references.

Some of these shapes are normalized again by JSON persistence/readback, hiding
the non-canonical caller input after the durable write.

An exact empty tuple is intentionally valid because existing domain/webapp
flows create manual findings without evidence.

## Acceptance contract

Before the finding INSERT:

- `evidence_ids` is an exact built-in `tuple`;
- an exact empty tuple remains valid for intentional manual findings;
- every supplied entry is an exact built-in `str`;
- every supplied reference is non-blank;
- supplied references are unique;
- malformed input raises `ValueError`;
- rejection leaves the durable findings table unchanged;
- canonical readback preserves the original evidence-reference sequence.

## Layering

This is a defense-in-depth durable persistence contract. It does **not** make
evidence mandatory at the general domain API.

- #848 owns canonical finding-local evidence shape at `persist_lab_findings()`;
- #850 owns mandatory evidence presence specifically at that lab-sync bridge;
- #849 owns polymorphic `FindingRecord` admission during lab retest;
- #851 owns canonicality of optional evidence at the lower-level write boundary.

## Collision boundary

Active PR #828 already modifies `src/lightup/domain.py` for finding-read
tenant-lineage enforcement. The source repair for #851 should therefore stack
above #828 rather than competing with it.

The acceptance branch itself remains tests/docs only.

## Safety

Temporary-SQLite durable-data integrity proof only. No DNS/network access,
target interaction, evidence collection, capability execution,
remediation/retest execution, deployment, security verdict creation or
attack-path mutation.
