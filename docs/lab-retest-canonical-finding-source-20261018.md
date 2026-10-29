# Canonical internal-lab retest finding admission · issue #849

**Stage: INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.** This is a source-only denial guard. It does not initiate any observation, run a retest or authorize a target.

## Defect closed at the call boundary

In the existing internal-lab retest bridge, `retest_finding(store, ctx, finding)` selected `check_id` using the caller's `finding.title` before comparing that supplied finding to its reloaded persistent record. A producer-impossible `FindingRecord` subclass could override equality to match an unrelated durable finding while returning a different known-check title. Once `check_id` had been selected, replacing `finding` with the persisted record did **not** replace the selected check, risking a wrong retest status.

## Source change

The first executable statement in `retest_finding()` now requires `type(finding) is FindingRecord`. A noncanonical object is rejected with `LabIsolationError` **before consulting its engagement, client, title, finding identity or equality, before querying a target and before calling the baseline observer**. Exact built-in `FindingRecord` instances retain the existing engagement/tenant checks, durable comparison, check selection and status update. No new network call or target capability is introduced.

## Source integration

This branch starts at the existing [lab evidence source #854](https://github.com/Zennay/Lightup/pull/854) exact head `19f7b11db3911feb656fdf18319c15f20b453239`, retaining canonical evidence-reference admission #848/#850 and parent #184. Historical acceptance-only issue #849 branch is not altered. Changes: this source file and this document, not the original source owner or any test/CI file.

Not a proven live fix or permission to retest. Existing exact-head hosted and permanent registered VPS CI, original source owners, independent privacy/security and research integrity review, genuinely authenticated separate client/operator authorization and action-time revocation, plus explicit HUMAN GO remain mandatory before any merge/deploy/active observation. No QA/regression suites created or manually run under the 17 October directive. **NO MERGE, DEPLOY OR LIVE RETEST WHILE HOLD.**
