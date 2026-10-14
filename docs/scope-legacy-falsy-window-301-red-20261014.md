# LightUp #301 — falsy legacy authorization time boundaries (RED)

This is a **synthetic-only acceptance pack** for [issue #301](https://github.com/Zennay/Lightup/issues/301), on its own branch from unchanged `main`. The problem is that legacy `Authorization.is_current()` treats falsy invalid objects as though `valid_from` / `valid_until` were omitted. `0`, `False`, `""` and `()` can erase a temporal boundary without being legitimate `None` values.

The exact legacy `Authorization` production code is actively owned by [PR #100](https://github.com/Zennay/Lightup/pull/100) / #104. These changes **only add new tests and documentation**. Do not alter or merge over source-owner work.

## Tests and interpretation

`tests/test_scope_legacy_falsy_window_301_red_20261014.py` contains in-memory true UTC controls, intended inclusive end/start boundaries (issue #295), explicit valid `None` semantics, negative expired/future controls and two pure `ScopePolicy` decisions. Ten `@unittest.expectedFailure` tests deliberately reproduce invalid falsy from/until values and show that malformed authorization metadata can be incorrectly admitted even by a syntactic explicit-host scope gate. No socket, DNS, handler, executor, SQLite, customer grant or target I/O occurs. The chosen `.example.test` host is never resolved.

`tests/test_scope_legacy_falsy_window_301_red_witness_20261014.py` separately reruns exactly these ten RED canaries under a private `unittest.TestResult`, proving they are genuine assertion failures and not masked unrelated crashes or XPASS. Even passing all tests with ten expected failures is **not** a repaired authorization boundary.

## Repair handoff

1. Production source owner must enforce `type(valid_from) is datetime or valid_from is None` and the corresponding check for `valid_until`. Timezone-naive values and invalid types must deny or raise explicitly **before** any authorization can appear current.
2. Preserve existing aware UTC comparison and canonical inclusive bounds; reject any malformed persisted or programmatic field instead of treating it as unspecified.
3. Remove all ten `@unittest.expectedFailure` annotations after the code is corrected; require each formerly RED test to pass normally.
4. Compose with source-owner changes, validate original raw Python 3.11/3.14 CI and registered permanent VPS evidence, obtain independent security/privacy review before activation.

Run offline:

```bash
python -m unittest discover -s tests -p 'test_scope_legacy_falsy_window_301*.py' -v
```

**INCUBATE M3/M7 · PLAN/LAB ONLY.** A positive `ScopePolicy` decision is merely a synthetic observation here. It does not certify genuine ownership, customer consent or a permit. No production deployment or real target assessment is authorized.

## W2 real in-process ActivationGate boundary (new acceptance)

`tests/test_scope_legacy_falsy_window_activation_red_301.py` adds
**four additional expected-RED** original-source tests for the real
`ActivationGate.issue()` **AUTHORIZED** path, with explicitly configured
synthetic scope and a never-resolved `fixture.example.test` hostname.

- A falsey invalid start/expiry (`False`, `0`) passes legacy
  `Authorization.is_current()` truthiness checks in the real in-process
  gate and can result in creation of a **fictional in-memory permit**.
  This is a security regression witness, **not actual consent, a real
  deploy/scan permit or any execution capability**.
- Canonical future/expired UTC and PLAN_ONLY/LAB_ONLY negative controls
  remain ordinary PASS, with no socket, DNS, target adapter, real
  authorization, external state or customer interaction.
- An ordinary integrity test reruns the four expected REDs under a
  private unittest result and refuses masked errors or unexpected
  successes. When the source owner fixes the defect, convert all four
  expected REDs to normal passing tests; do not mistake a masked
  failure or hosted green XFAIL for genuine safety.

The original `ActivationGate` and legacy `Authorization` production
files remain **unmodified**, including owner #100/#104. This adds
synthetic acceptance to the already-owned #301 PR without overlapping
another worker.

```bash
python -m unittest discover -s tests -p 'test_scope_legacy_falsy_window_activation_red_301.py' -v
```
