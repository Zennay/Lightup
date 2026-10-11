# Evidence-remediation W23 — legacy Finding evidence exact-type adversarial acceptance

Status: **EXPECTED RED / DRAFT HOLD**. Related open issue [#894](https://github.com/Zennay/Lightup/issues/894).

## Narrow proof boundary

An in-memory `Finding` can carry arbitrary Python evidence despite its `list[str]` hint. The legacy `Finding.validate()` in current `main` validates only identity, title, target, and remediation; downstream Markdown rendering iterates the evidence collection. This *synthetic admission robustness gap* is not a real assessment or a claim of exploitable behavior in a deployed service.

`tests/test_legacy_evidence_exact_types_adversarial_20261011_w23.py` exercises:

- Exact built-in `list` admission; tuples, mappings, strings, `None`, and a hostile `list` subclass are refused **before subclass methods can execute**.
- Exact built-in, nonblank `str` elements; subclass, booleans, bytes, numbers, `None`, and whitespace-only late elements are refused without coercion or changing caller-owned evidence.
- Valid multilingual Unicode and intentional spacing preserve order and object identity; the existing empty-list "No evidence recorded" fallback remains.

These are **contract assertions against a future source-owner fix**, not expected-green acceptance of the unchanged default branch. The test is intentionally failing (RED) against `main`; do not treat RED as a live system security failure or merge it alone into green-required `main`.

## Ownership and release

`src/lightup/models.py` is owned by existing #100 and `src/lightup/reporting.py` by #732. This branch changes **neither** file; original default routes/domain/retest and any target/policy gates remain unchanged. Have the respective owners integrate the narrowly scoped validation, run all suite and exact-head permanent VPS CI, perform independent security/evidence review, and only then consider merge. No live tenants, targets, authorization grants, scans, remediation execution, proof of actual vulnerabilities, retest, deployment, or data mutations.

Project remains **M3/M7 PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY**.
