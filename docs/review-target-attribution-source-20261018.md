# Finding-local target attribution in review and report

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Source-only change; not a live assessment or release decision.

## Original defect · #847

The planner can produce findings for several different concrete targets. The existing verifier and remediation advisor already saw each finding's original target, but `ReviewedFinding`, `ReviewResult.to_dict()` and the report-synthesizer's list of findings lost it. An otherwise valid advice entry could therefore be presented without the asset it belongs to.

## Implemented consumer contract

* Review performs whole-batch admission before the first model call, inheriting the evidence/ref/fix gate from the original #1179 → #1602 review source. Each original finding's `target` (or the exact existing run-level `target` / comma-joined `targets` fallback) is snapshotted at that point.
* The selected target must be bounded built-in, nonblank text. A malformed planner target collection is not silently stringified and a malformed finding fails closed before even the first verifier request. The existing fallback is used only when the finding does not specify `target`; an explicitly empty finding target is not silently replaced.
* Verifier and remediation advisor payloads, the immutable `ReviewedFinding` object, `ReviewResult.to_dict().findings[]` and `REPORT_SYNTHESIZER`'s `findings[]` all receive the **same** exact finding-local string, in unchanged original finding order.
* All other existing finding fields, source evidence, verdict sequence and original fixes remain on their existing path; the run-level report target label is unchanged in meaning.
* This feature changes metadata in a report only. It does not establish client identity, target authority, evidence truth or security outcome, and it never executes tools, scans or fixes.

## Composition and release

This child branch is based on exact original head `09da2cb59fb4ba9cbc1318c626429c92e6ee6fb5` of #1602, which itself preserves parent #1179 and original #846. It changes only `src/lightup/ai/pipeline.py` plus this file. Historical issue #847 has an older unmerged 2026-10-07 branch; its metadata-preservation intent is absorbed into this newer source chain without taking over that branch, tests or claims.

Existing strict payload-snapshot assertions from earlier source PRs may require original owners to consciously accept the additive per-finding `target` shape; none were edited under the no-QA user directive. Genuine mandatory exact-head hosted AND permanently registered VPS CI, source-owner review, independent privacy/security acceptance, separate authenticated client/operator consent with revocation at action time and explicit HUMAN GO remain unsatisfied until actually evidenced. **Do not merge, deploy or activate while DRAFT/HOLD.**
