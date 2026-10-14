# Scope approval window: microsecond boundary acceptance reference

**Status:** M7/ST5 offline acceptance only; not production authorization, permission, or release proof.

A grant's validity window should be treated as a half-open interval in absolute time, `[valid_from, valid_until)`. The start instant is inclusive and the expiry instant is exclusive, without rounding to seconds or local wall-clock comparison. Zero-length and reversed intervals deny. All inputs must be exact timezone-aware `datetime` instances; malformed, naive, missing and non-datetime inputs deny. Equivalent offset representations of the same instant must lead to the same result.

The isolated tests define ten reference-model regressions including microsecond start/end edges, timezone equivalence, naive and malformed types, and invalid windows. The reference predicate is **not called by production code** and should never authorize an actual tool, scan, network request or target.

Production owner PR #107 must verify its trusted clock, issuer provenance, tenant/asset/risk/capability bounds, revocation fencing and runtime dispatch using the real integrated executor. In particular, wall-clock rollback and concurrent revocation cannot be established by this pure reference model. No source-owner files, runtime policy or other workers' branches are changed.

## Reproduce

```bash
python -m unittest discover -s tests -p 'test_scope_half_open_time_boundary_reference_20261008.py' -v
```

**Promotion:** exact-head hosted CI plus permanent VPS tests, owner review and integration required. A green reference suite alone cannot activate any target.
