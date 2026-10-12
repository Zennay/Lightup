# W10 — post-admission deletion and alias-mutation atomicity

Tracked open issue: [#936](https://github.com/Zennay/Lightup/issues/936). Immutable parent is v9 composition head `304d2a3b8c1cce8c2af5ef09a7a01c8406ebc244`, which already owns the v8 mixed-admission atomicity matrix. Production owner remains [draft #175](https://github.com/Zennay/Lightup/pull/175).

## Additional failure modes isolated by this child

Earlier v9 tests cover malformed signal admission, direct `append`, whole-collection **assignment** and identity **assignment**. They do not exercise **deletion** or all in-place collection mutations after a valid admission.

This tests-only W10 child adds `tests/test_discovery_post_admission_deletion_atomicity_w10.py`:

- Eight intentional `@unittest.expectedFailure` canaries: delete `prospect_id`, delete `organization_name`, delete `signals`, delete a signal item, in-place multiply to erase signals, slice replacement with interactive data, extend with non-public data, and pop a valid signal.
- Two ordinary positive producer controls: eight repeated rejected signals after an admitted snapshot, and a later interactive rejection after two valid signals with preserved order/aggregate confidence.
- Every intended rejection is verified against existing admitted identity, **exact immutable tuple** collection and unchanged aggregate confidence. Inputs are invented; no coercions or external reads.

## Interpretation and source-owner repair

The pinned producer's `ProspectProfile` is a mutable dataclass exposing a list; the eight XFAIL canaries document expected RED. **An XFAIL is neither a fix nor a passing authorization gate.** Production owner #175 must choose and implement a consistent immutable snapshot representation, prohibit identity deletion/rebinding and prevent mutable aliases/collection mutation, then turn these eight canaries into **ordinary passing tests**, not blanket exceptions. Legitimate `add_signal` admission must continue to work and validated signals must retain chronological order. Avoid mutating arbitrary caller-owned input, and verify empty and admitted profile behavior.

Test-only reproduction on the exact branch snapshot:

```sh
PYTHONPATH=src python -m unittest -v tests.test_discovery_post_admission_deletion_atomicity_w10
```

Expected pre-repair local result: 10 methods: 2 ordinary pass and 8 intentional expected failures. This is **not** asserted as CI-verified; read raw exact-head logs for actual acceptance evidence. Existing v8/v9 regressions may still be RED and cannot be silently skipped in a release suite.

## Isolation and release gates

Only **new** docs/test files may be added to this child. Do not edit #175 source, parent v9 test files, other scope owner branches or evidence-remediation. This is passive synthetic in-memory acceptance only: no targets, network, DNS, scanners, grants, execution, persistence, live clients, remediation, merge or deployment. Keep **Incubate M3/M7 / PLAN-LAB ONLY / DRAFT-HOLD / NO MERGE / NO DEPLOY**. Owner, independent security/privacy review, green integrated current-main test suite on Python 3.11/3.14 and registered permanent VPS at exact approved SHA, and explicit human release signoff remain mandatory.
