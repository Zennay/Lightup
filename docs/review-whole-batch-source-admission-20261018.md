# LightUp · atomic original evidence/remediation admission (review-only)

**Original source owner:** [PR #846](https://github.com/Zennay/Lightup/pull/846) · **Preferred original acceptance composition:** [#902](https://github.com/Zennay/Lightup/issues/902) · **Whole-batch outstanding acceptance:** [PR #1179](https://github.com/Zennay/Lightup/pull/1179), exact parent `72c5c7bd2e31300b6a2787d6f4cf2586f40c3296`.

## Delivered product behavior

Original default `AssessmentReviewPipeline.review()` now has a **single whole-batch source-intake boundary** ahead of verifier/advisor/report model requests. This addresses three already-existing defect reports without introducing a new model or allowing any targets or tools to run.

1. **#899: source evidence references.** Each finding must have a bounded, non-empty collection of distinct exact built-in string evidence IDs, preserving original order and original display values. Malformed, duplicate, empty or polymorphic IDs fail with a controlled `ValueError`, *before any model role is contacted*, including when the invalid item occurs later in a multi-finding batch.
2. **#901: current remediation text.** Every finding requires the exact built-in nonblank `fix` string, bounded to 8192 original characters. Legitimate spaces are deliberately preserved (not stripped, normalized or coerced) through the advisor's `current_fix` input. A blank, non-string or forged string-subclass input causes no model requests, even if preceded by valid findings.
3. **#898: advisor output.** Before a derived `ReviewedFinding` or report payload can contain an advisor reply, the reply must be exact built-in nonblank text, <=8192 characters, UTF-8-encodable and <=16384 encoded bytes. Blank/malformed/oversized text aborts before `REPORT_SYNTHESIZER`. The original text itself is not rewritten or granted the status of a verified fix.

The admission routine bounds the input finding count to 64, and rejects missing, polymorphic, blank or oversized **original finding title, severity and impact** values in any source case **before** sending even the first case to the verifier. Title and impact are limited to 4096 original characters; severity to 64. These were already required fields consumed by the original pipeline; admitting them ahead of time prevents a malformed second finding from causing partial model dispatch. It captures source field snapshots without mutating original dictionaries/lists and preserves the existing separate `VERIFIER` → `REMEDIATION_ADVISOR` → `REPORT_SYNTHESIZER` sequence for valid inputs. It never issues its own independent verdict or sends actual raw evidence bytes.

## Collision and mandatory gates

This is a *source-only* successor above the exact existing [PR #1179](https://github.com/Zennay/Lightup/pull/1179) head, which itself includes #846 and the older #902 review acceptance pack. No original source-owner branch, existing test, expected RED, fixtures, runner, CI or model gateway file is edited. The parent acceptance modules remain existing untouched artifacts and must be adjudicated by the independent owners through mandatory CI. No QA, regression or tests have been authored, altered or run in this work.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Model output is still untrusted. No external model requests were executed in this implementation run; no target I/O, scanning, tool/handler dispatch, grants, real credentials, remediation/retest execution or report distribution. Original exact-head hosted and permanent named VPS CI, relevant source-owner fixes and integration review, independent security/privacy review, genuine distinct authenticated client/operator consent with action-time revocation and explicit HUMAN GO remain necessary. No merge or deploy without them.
