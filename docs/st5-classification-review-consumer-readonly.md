# ST5 classification-review consumer read-only contract

Issue: #334

This tests/docs-only child of exact PR #109 proves that the composed persisted
classification-review consumer is observationally read-only not only with
respect to persisted caller input, but also across the complete live lineage
and the SQLite state consulted during validation.

## Boundary

Base: `ad7f54c7a94467eefbc1f9ef9582ac849cb08175`.

The existing consumer performs:

1. persisted input decode and strict parsing;
2. complete live evidence-remediation revalidation;
3. return of the canonical classification-review request only if both stages
   remain valid.

No production implementation is changed by this gate.

## Read-only proof

The regression uses the real #109 producer fixture and snapshots every produced
typed artifact/context/operator value plus all rows in:

- `runs`;
- `capability_leases`;
- `evidence`.

A successful consumer round-trip must leave every snapshot unchanged.

A second path keeps persisted input canonical but substitutes a stale live
attestation digest. Strict parsing therefore succeeds before live lineage
validation rejects reuse. That rejection is executed twice and must:

- return the same failure message;
- leave every typed live input unchanged;
- leave every StateStore row unchanged.

This prevents a validation path from turning a read/check operation into an
implicit state transition or partial write.

## Safety stop line

The gate creates no classification decision or transition resolution and grants
no collection, tool, target, execution, remediation, retest, deployment or
attack-path authority. It does not invoke an external model or interact with a
target. Future semantics remain unresolved and no security verdict is created.
