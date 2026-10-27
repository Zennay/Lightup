# LAB_ACTIVE exact lab attestation acceptance (expected RED)

The `ExecutionPolicy.decide()` LAB_ACTIVE branch currently uses `if not request.is_lab`, which treats truthy non-boolean data as proof of an isolated lab. Python accepts `1`, `"yes"`, and nonempty collections as truthy.

## Required invariant

- Only the exact built-in boolean `True` proves the LAB_ACTIVE lab flag.
- `False` and every noncanonical value (including integer `1`, strings, collections and arbitrary objects) must deny.
- Do not infer lab tenancy, ownership, environment isolation or real-target permission from this flag alone. Existing external isolation and admission controls must remain independently enforced.
- Deny before dispatch or other side effects; never silently coerce untrusted input to `bool`.

## Proof

`tests/test_scope_lab_flag_exact_bool_acceptance.py` uses only in-memory policy calls and an invalid test-only asset name. The five malformed positive cases are expected RED on current `main`; the `True` and `False` controls should pass.

## Ownership and release

This is an isolated tests/docs-only contract, not a fix. Production `src/lightup/execution_policy.py` belongs to its existing owner and must not be modified in this sidecar. Owner should absorb a narrow fail-closed identity check, review effect on legitimate callers, and validate both the exact-head hosted preflight and canonical permanent-VPS CI before merge. Do not treat passing tests as authorization to execute real targets. No scanning, target I/O, network testing, workflow dispatch, or deployment is included.
