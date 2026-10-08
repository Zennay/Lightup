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
