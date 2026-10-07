# Persisted recurring-retest authority must remain canonical

Issue: #870

## Boundary

Authorization grants persist `recurring_retest_allowed` as an integer flag. The
read boundary must not infer authority from arbitrary SQLite truthiness.

Canonical storage has exactly two states:

- `0` -> `False`
- `1` -> `True`

Every other stored value is corruption and must fail closed.

## Current gap

Current grant reconstruction uses:

```python
recurring_retest_allowed=bool(row["recurring_retest_allowed"])
```

That silently normalizes values outside the issuance contract. For example, a
persisted integer `2` or text `"false"` reconstructs as `True`.

Because recurring-retest permission is authority-bearing, storage corruption must
never mint that permission.

## Acceptance contract

- persisted exact integer `0` reconstructs as exact built-in `False`;
- persisted exact integer `1` reconstructs as exact built-in `True`;
- noncanonical integers fail closed;
- noncanonical text fails closed;
- rejected reads do not rewrite the corrupted row;
- no normalization, clamping, string parsing, or generic `bool(...)` coercion is
  allowed.

## Expected RED

Against current `main` the canonical 0/1 control is green. The two corruption
cases are expected RED because both are currently normalized by `bool(...)`
rather than rejected.

## Collision boundary

This acceptance slice adds tests and documentation only.

It is separate from #868:
- #868 owns issuance-time Python input typing;
- #870 owns durable reconstruction of the stored flag.

No active grant read/resolver source is modified by this branch.

## Safety

Temporary SQLite corruption proof only. No DNS/network I/O, target interaction,
scanning, capability execution, remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
