# Finding evidence integrity across read selectors

Issue #883 extends the persisted finding-evidence acceptance contract in #856
without taking production-source ownership from #828.

## Why this exists

`DomainStore.list_findings()` has three query branches:

1. explicit engagement scope;
2. client/tenant scope;
3. operator-wide audit scope.

All three eventually pass rows through the same finding reconstruction boundary.
Malformed durable evidence must therefore fail closed identically regardless of
which selector produced the row.

## Required behavior

- canonical evidence remains readable through all three selectors;
- malformed persisted evidence fails with the evidence-integrity error through
  all three selectors;
- a rejected read is observationally read-only and leaves the corrupt
  `evidence_ids_json` value unchanged;
- #828 tenant-lineage filtering remains the query authority boundary.

## Non-overlap

This branch adds tests/docs only. It does not modify `src/lightup/domain.py`,
write-side finding evidence (#857), labsync (#854), Security Twin projection,
scope authorization, target-capable paths, deployment, verdict creation or
attack-path mutation.

## Safety

The proof uses only temporary SQLite reads. It performs no target interaction,
network I/O, evidence collection, capability execution, remediation/retest
execution or deployment.
