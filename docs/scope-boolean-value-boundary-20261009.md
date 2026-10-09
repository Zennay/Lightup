# BOOLEAN tool argument boundary (offline acceptance)

This branch adds `tests/test_scope_boolean_argument_boundary_20261009.py` against current `main` without changing production code. Run with `PYTHONPATH=src python -m unittest discover -s tests -p test_scope_boolean_argument_boundary_20261009.py`. The earlier accidental `InteractionKind.PLAN_ONLY` reference was corrected to the existing `InteractionKind.ANALYSIS` with `RiskLevel.ANALYSIS_ONLY`; the matrix additionally verifies that `bool` cannot be smuggled into INTEGER/NUMBER and optional BOOLEAN never coerces integer zero. No workflow execution has yet established pass/fail on the new head.

`ParamKind.BOOLEAN` must accept the exact Python `True` and `False`, reject integer/float/string lookalikes and missing required arguments, and reject unknown keys without mutating caller data.

This is a **schema-only, offline positive/negative regression**, not evidence that persisted customer consent, trusted destination binding, revocation checks or actual executor dispatch are safe. No handlers, grants, scanning, network or deployment are involved. This test-only branch intentionally avoids source currently owned by #107 and #156, the duplicate-key lane #966 and Draft #1146. Keep DRAFT/HOLD and do not promote to target execution absent production owner integration, source review and exact-head hosted plus canonical permanent VPS evidence. No CI runs have been claimed for this branch.

## Rejection state integrity

The schema-only suite also checks that a rejected string impersonating BOOLEAN leaves caller input unchanged; a subsequent exact `False` and `True` remains admissible. Mixed valid BOOLEAN with an unknown field is rejected without mutation, regardless of the BOOLEAN value. These checks are limited to `ToolDefinition.validate_arguments` and cannot establish zero handler calls or persisted-evidence absence in actual ToolExecutor execution.

PR #1148 initially queued hosted preflight run [37950026884](https://github.com/Zennay/Lightup/actions/runs/37950026884) and canonical CI [37950027153](https://github.com/Zennay/Lightup/actions/runs/37950027153) for older HEAD `58c101d`. They were QUEUED at inspection, not successful proof, and do **not** validate this later commit. Do not rerun old jobs or treat their result as current-head acceptance.

## Cross-tool schema isolation (added 2026-10-09)

A separate inert STRING tool with an identically named `enabled` parameter is validated independently. `True` is admitted only by the BOOLEAN schema, while the literal `"true"` is admitted only by the STRING schema. Both crossed forms must be denied. This covers standalone schema identity only; it does not verify production `ToolRegistry.get` binding or executor dispatch. The previous head `c05e962` hosted preflight Python 3.14 completed success, Python 3.11 was in progress, and both permanent VPS jobs were queued at inspection. Those runs cannot prove the updated test at this branch head.

## Repeated admission contract

A single immutable schema definition is reused for successive positive and negative validation attempts (`True`, `False`, `"true"`, `1`, `None`, `False`, `True`). Every rejection must preserve the same declared parameter tuple and subsequent canonical booleans must remain accepted. This establishes schema-only call-sequence invariance, not ToolExecutor cache safety or policy authorization.

Prior HEAD `5580c50272a368cc62a004032c1f27f812c64f44` queued canonical run [37950370644](https://github.com/Zennay/Lightup/actions/runs/37950370644) and had hosted preflight [37950370842](https://github.com/Zennay/Lightup/actions/runs/37950370842) in progress when checked. These results are not current-head evidence after this test addition.
