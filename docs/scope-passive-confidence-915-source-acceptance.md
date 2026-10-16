# #915 — exact built-in float for passive-discovery confidence

Status: **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**.
This artifact is stacked directly above the existing discovery source-owner
PR #175, pinned commit `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.
It changes no source-owned `src/lightup/discovery.py` files.

## Why this is a source-owner RED

`ProspectSignal.validate_for_unauthorized_discovery()` currently checks
`0.0 <= confidence <= 1.0` without checking the exact builtin type first.
Boolean and integer values `False`, `True`, `0`, `1` compare numerically
as valid, and an untrusted `float` subclass can override rich comparisons
to claim `3.0` is in range. This is a metadata-admission integrity problem;
it does not by itself prove target execution or consent bypass.

## Required owner repair

1. Before any numerical comparison: `type(signal.confidence) is float`.
   Reject all other types with controlled `ValueError` (no coercion).
2. Preserve exact `0.0`, interior floats, `1.0` as valid; exact
   out-of-range floats and `NaN` remain invalid.
3. Reject invalid signals before mutating the profile; preserve all
   preexisting admitted objects and caller input. No silent normalization.
4. Do not change source-owned passive discovery boolean contracts,
   activation, execution policy, scopes, target-capable components or CI.

## Test / promotion

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_passive*_915.py' -v
```

Seven canonical PASS tests, seven deliberate expected **source RED** tests
on the pinned PR #175. The additional `tests/test_scope_passive_precomparison_915.py` rejects non-canonical floats **before any attacker-controlled `__ge__` or `__le__` runs**, including a throwing comparison override. A source-type check after rich comparison is too late. After the owner's source fix, remove the
`@expectedFailure` decorators, demand all 14 ordinary PASS on Python
3.11 and 3.14, then verify exact-head whole-repository hosted and
genuinely registered canonical VPS CI before any deployment. The isolated
hosted matrix is not evidence of authorization, independent client/operator
consent, privacy/security clearance, at-use revocation, or human GO.
No live discovery, scans, grants, target interactions, tool execution,
merge, deploy or release in this review slice.
