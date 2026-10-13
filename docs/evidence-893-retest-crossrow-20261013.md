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


## Audit-trigger durability supplement (second pass)

New add-only `tests/test_evidence_893_retest_audit_trigger_red_20261013.py` proves another consequence of the installed post-write evidence decode: real temporary SQLite `AFTER UPDATE OF retest_status` audit rows must **not** persist when corrupt JSON/object evidence refuses a metadata transition. Two positive controls prove one canonical event and zero events for unknown finding; two explicit **expected-RED** canaries demand no status and no audit side effects on malformed persisted evidence. These tests use only synthetic fixtures and unchanged default `DomainStore`; there is no claim of a real retest or fixed source.

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_893_retest_audit_trigger_red_20261013
```

This branch now contains **four new tests/doc files** across two passes. It remains branch-only, without duplicate PR or shared VPS dispatch; no exact-head CI success is claimed. #1178 already owns the separate opt-in atomic metadata helper, so this child edits neither that helper nor `domain.py`. A production source owner must fix read-before-write/transaction rollback and convert all RED contracts to normal green cases.

## Exact status enum / durable mutation supplement (2026-10-13)

Another independent add-only module, `tests/test_evidence_893_status_type_atomic_red_20261013.py`, has seven real temporary SQLite acceptance methods: three passing controls (canonical operator enum persists, client-member denial leaves rows intact, unknown finding denial is atomic) and **four intentionally expected RED** status-input contracts. The unchanged `DomainStore.set_retest_status` currently reads `status.value` without requiring an exact `RetestStatus` enum, so objects can forge a valid string status or commit invalid persisted status text/boolean before `_finding_from_row` fails. A plain string yields an incidental `AttributeError` rather than a deterministic denial. All negative tests require refusal **before any SQLite mutation** and unchanged reopened durable rows. These remain source-owner evidence, not an installed repair.

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_893_status_type_atomic_red_20261013
```

Source-owner remediation must validate `type(status) is RetestStatus` before opening the database, recheck persisted evidence integrity and wrap status transition and decode in one atomic transaction. Keep #893 OPEN and convert these intentional RED to ordinary PASS after original #828/#856 decoder and `DomainStore` owners approve. No separate PR or runner retrigger from this branch; no exact-head CI claimed here.
