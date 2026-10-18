# LightUp · canonical offline evaluation metrics at source

**Original issue:** [#834](https://github.com/Zennay/Lightup/issues/834) · **Existing context-binding owner:** [PR #169](https://github.com/Zennay/Lightup/pull/169) · **Original pre-existing acceptance contract:** [PR #835](https://github.com/Zennay/Lightup/pull/835)

## Delivered source behavior

This source-only successor is based **exactly on PR #835 at `a873e3c5139d7703ea1d96438f2398a6c4cde686`**; it preserves the original #169 foreign-context binding and keeps the original #835 source-integrity acceptance files unchanged.

The actual `EvaluationMetrics.validate()` now refuses:

- boolean, fractional, negative, or non-canonical Python numeric *counter* values. All nine lab counters must be exact built-in nonnegative integers;
- boolean, out-of-bounds, non-finite, or polymorphic *quality scores*. The four scores accept exact built-in ints/floats in the closed `0..1` interval;
- boolean, negative, NaN, Infinity, polymorphic or unrepresentably large *runtime/cost* values. Those two source numbers must be finite and nonnegative.

`LabEvaluationHarness.record()` now also requires the **exact** `EvaluationMetrics` built-in dataclass type, calls its source validation before creating and appending a record, and leaves `records` unchanged if invalid. This prevents duck-typed/subclass overridden `validate()` from bypassing lab result integrity.

`EvaluationRecord.to_dict()`, and hence `to_json()`, validate exact canonical metrics before generating a serialized lab result or deriving false positive rates, closing the read/hand-off route for an otherwise directly constructed invalid record.

## Scope and release hold

- No new or modified tests or QA suite; original unmodified #835 acceptance requirements remain in force and must be evaluated through original CI by the proper source/review owners.
- No scanning, target access, authorization, consent, grants, real evaluation run, network action, tool execution or persistence migration is introduced.
- No edits to source-owner #169 branch or original #835 branch and no merge of either without original dependency gates.
- **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Changes must not be merged/deployed as production until independent security/privacy review, distinct authenticated client/operator consent and action-time revocation, exact-head hosted and named VPS CI, relevant source-owner issue remediation and explicit HUMAN GO are satisfied.
