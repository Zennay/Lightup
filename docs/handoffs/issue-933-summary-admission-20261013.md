# Issue #933 — passive prospect summary admission acceptance (tests only)

## Ownership and base
- Source owner: draft PR #175, exact parent `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.
- Child branch: `chatgpt/lightup-933-summary-acceptance-20261013-1630`.
- This branch adds **only** dedicated regression tests and this handoff; it must not change `src/lightup/discovery.py`, production activation, main, or another worker's files.
- Main observed at review: `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`.

## Acceptance and reproducibility
```sh
PYTHONPATH=src python -m unittest -v tests.test_discovery_933_summary_contract_20261013
```

Seven offline unittest methods: two ordinary positive/boundary tests and five intentionally marked `expectedFailure` because the source owner has **not** implemented the missing runtime summary admission. These cover exact built-in `str`, no coercion or caller-polymorphic subclasses, Unicode whitespace, unchanged canonical text, and atomic profile refusal. An `OK (expected failures=5)` result is **not** a fix and must not be used to close the issue.

## Required source-owner work
1. In the existing PR #175 owner path, check `type(signal.summary) is str` and `signal.summary.strip()` for non-empty content **before** mutating `ProspectProfile`. Preserve accepted original text without trimming or coercion.
2. Convert all five `expectedFailure` markers into ordinary tests after implementing the source fix; verify all seven tests pass without XFAIL/XPASS and run the full suite.
3. Verify exact-head GitHub-hosted Python 3.11/3.14, separately registered permanent VPS runner, current-main compatibility, and explicit reviewer/security approval before merge or closing #933.

## Safety and state
LightUp is INCUBATE M3/M7, PLAN/LAB ONLY. No network/target interaction, scanning, live client records, grant issuance, tenant mutation, active capability, remediation/retest, deployment, or production authorization is performed here. This child is DRAFT/HOLD and **must not merge independently**. PR creation was refused by safety checks on 2026-10-13; the branch is still a committed, inspectable artifact. No exact-child-head CI exists until a supported workflow is triggered.
