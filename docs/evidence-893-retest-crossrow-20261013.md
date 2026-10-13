# Evidence remediation #893 — cross-row durable retest atomicity (2026-10-13)

This is a strictly **tests/docs-only**, branch-only child of the existing evidence read contract head `f0b0025b2c95f88c2fbd4bf2340ae5e05578bc1e`. It does not change `src/lightup/domain.py`, the #828/#856 source owners, any report/export code, `main`, or other worker branches. Existing #893 acceptance is preserved.

## New offline proof

`tests/test_evidence_893_atomic_crossrow_20261013.py` creates two real synthetic findings in one disposable SQLite database and performs read-only row snapshots before/after status mutation attempts.

- Two canonical transitions pass and persist after reopening SQLite.
- Unknown finding IDs cannot change other rows.
- Four **intentional `@unittest.expectedFailure` RED canaries** demand that an invalid JSON document, JSON object, duplicate evidence references or `null` evidence refuse a status transition without touching any row.
- The failing negative canaries assert a deterministic evidence-integrity `ValueError`, complete before/after-row equality, and durable equality after database reopening. One scenario starts after another finding was marked fixed; another starts from `FIX_PENDING`.
- A reported `expected failure` documents the original producer gap; it **does not** mean a security fix was installed. Converting RED into ordinary PASS requires the actual #856/886 decoder and `set_retest_status` atomic transaction/read-before-write owned by source maintainers.

## Validation and release

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_893_atomic_crossrow_20261013
```

Run full exact-head hosted Python 3.11 and 3.14 tests plus **separate permanent registered VPS CI** only when a source-owner-approved composition is ready. Keep this branch **branch-only** to avoid duplicate PRs and contention for the shared runner. No CI is claimed for this child until observed. No real target, remediation action, retest observation, authorization, deployment, or new security-verdict authority is created.

LightUp **Incubate M3/M7 — PLAN/LAB ONLY / DRAFT HOLD / NO MERGE / NO DEPLOY**. Keep issue #893 OPEN and hand off to #828/#856/#886 source owners with privacy/security/tenant review, latest-main integration and explicit release approval.
