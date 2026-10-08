# Scope authorization: denial monotonicity (offline reference)

This isolated acceptance pack models five *independent, explicit Boolean*
authorization gates: tenant active, grant current, scope matching, reviewer
validity and absence of revocation. Every gate must be `True` **with exact
Boolean type**. Missing/extra gate keys or non-Boolean values deny.

## Invariant

For any admission state, replacing one or more `True` gates by `False`
must never turn a denial into an allowance. The suite exhaustively checks
32 initial Boolean combinations and 32 restriction masks per combination,
plus malformed inputs, absent/extra keys and no mutation.

## Trust and integration boundary

This is a standalone reference predicate, **not** an integrated runtime
policy check, trusted issuer verifier, human approval, execution permit or
proof of production enforcement. It never touches real targets, network,
scanner, active executor or deployment. Production owner must bind gates
to trusted tenant/asset/capability/revision/clock and fresh revocation data
before making an admission decision, and test the actual executor boundary.

Work deliberately avoids PR #107 executor, #982 receipts, #992 reviewer
provenance, #983/#989 revocation and the parallel #1000–#1007 tests/docs.
No existing source or schema is edited.

Run offline:

```sh
python -m unittest discover -s tests -p 'test_scope_denial_monotonicity_reference_20261008.py' -v
```

Keep PR draft until **exact-head** hosted CI and canonical permanent VPS
runner proof, plus source-owner review, are recorded. Reference-model tests
cannot substitute for those gates.
