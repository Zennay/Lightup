# ToolCall duplicate-argument admission (RED regression)

## Boundary
A ToolCall retains ordered (name, value) pairs. Its `arguments_dict()` currently calls `dict(self.arguments)`, silently keeping the last value when a key occurs more than once. This is an ambiguous input at the typed-tool boundary; a malformed model/tool proposal must not be normalized into a different accepted call.

## Required behavior
- Reject repeated argument names **before** typed schema validation, policy decisions, handler calls, or evidence storage.
- Retain the existing mapping behavior for distinct argument names.
- Denial must be deterministic, fail closed, and free of side effects.
- Follow-up owner of `src/lightup/ai/orchestration.py` should implement the production fix without broadening execution authority.

## Scope / verification
The paired regression is `tests/test_toolcall_duplicate_argument_admission.py`. This branch is intentionally RED for its rejection assertion against current main. Run with `PYTHONPATH=src python -m unittest tests.test_toolcall_duplicate_argument_admission -v` in the normal CI / permanent runner lane. Do not interpret an expected RED test as successful full-suite validation.

This branch adds tests/docs only; it does not modify shared ToolExecutor production source, grant authority, contact a target, invoke a worker or start a deployment.

## Observed RED proof (2026-10-08)
Hosted offline preflight run [37705959681](https://github.com/Zennay/Lightup/actions/runs/37705959681) completed **failure**, as designed for this independent regression branch. Python 3.11 ran 541 tests with exactly one failure: `test_duplicate_key_must_not_silently_change_requested_value` raised `AssertionError: ... not raised`; 540 other tests passed. The Python 3.14 compile/unit step failed too. This demonstrates that duplicate keys currently pass unchallenged through `arguments_dict()`. A follow-up test also checks that even repeated equal values fail closed. Do not merge while RED; absorb into ToolExecutor owner's fix and rerun complete validation on the resolved commit.
