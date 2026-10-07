# Retest-status evidence atomicity

Issue #893 isolates a durable remediation/retest mutation boundary that sits immediately downstream of the persisted finding-evidence read contract in #856/#885.

## Gap

`DomainStore.set_retest_status()` currently performs these steps in this order:

1. update `findings.retest_status`;
2. re-read the row;
3. reconstruct the returned `FindingRecord` through `_finding_from_row()`.

The database connection uses SQLite autocommit. Therefore a malformed legacy/corrupt `evidence_ids_json` value can make the final decode fail only **after** the new retest status has already been committed.

The operation then reports failure while durable remediation/retest state has still changed.

## Required invariant

A finding whose persisted evidence cannot cross the canonical evidence-integrity boundary must not be partially mutated.

The focused acceptance module proves:

- canonical evidence still permits a normal retest-status transition;
- a JSON string shape that would otherwise be normalized into characters rejects before mutation;
- a `null` top-level value rejects before mutation;
- syntactically invalid JSON rejects before mutation;
- all malformed forms converge on the deterministic evidence-integrity `ValueError` owned by #856/#886;
- every rejected call leaves both `retest_status` and the original corrupt `evidence_ids_json` bytes unchanged;
- no repair, normalization, deletion or partial write is allowed.

## Composition and ownership

This tests/docs-only slice is pinned above the exact finding-evidence read-integrity pack head `7ea5fb7678967aa7f27916792d25a8c5897faa27`.

It deliberately changes no production source:

- PR #828 retains active finding-read query ownership;
- #856 retains the future persisted-evidence decoder/source successor;
- #857 owns write-side finding evidence validation;
- #854 owns lab evidence intake.

The future source fix should validate/reconstruct the current finding **before** committing the retest-status mutation, or otherwise execute validation and mutation atomically so a decode failure cannot leave durable state changed.

## Expected RED

On the pinned source, `set_retest_status()` updates first and decodes second. The string-shaped payload is currently normalized rather than rejected; invalid JSON leaks the decoder failure after the update; and `null` fails after the update. Once #856/#886's deterministic evidence decoder lands, these regressions should still expose the partial-write ordering until the mutation path is made atomic.

## Safety

Temporary-SQLite durable state testing only. No target/network interaction, scanning, evidence collection, capability execution, remediation execution, retest observation, deployment, security verdict creation or attack-path mutation.
