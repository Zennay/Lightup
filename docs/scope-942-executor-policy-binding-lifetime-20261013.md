# Scope #942 — Immutable canonical ExecutionPolicy binding in ToolExecutor

**Project:** INCUBATE M3/M7 PLAN/LAB ONLY — **DRAFT/HOLD, NO MERGE, NO DEPLOY**.

## Actual source boundary

The source owner [PR #107](https://github.com/Zennay/Lightup/pull/107) retains the executor's selected `policy` as a mutable public instance attribute. Even if original policy constructor validation and instance integrity (#779 and #935) are independently correct, later replacing `executor.policy` with an arbitrary allow-all duck object or subclass bypasses that validation before handler/evidence dispatch.

Issue [#942](https://github.com/Zennay/Lightup/issues/942) is specifically **executor policy binding lifetime**, not policy constructor object exactness or `ExecutionPolicy` own mutability. This new tests/docs-only branch directly pins the unmodified owner PR #107 exact SHA `c37ee27d922a7dd400eee1db39268f4a6269e431`; original #107 ToolExecutor and #100 ExecutionPolicy owners untouched. Neighbor branches #938 (resolver binding), #940 (registry binding), #949 (resolved grant), #951 (scope), #953 (temporal) independent and untouched.

## Offline acceptance delivered

New `tests/test_scope_942_executor_policy_binding_red_20261013.py` invokes real PR #107 `ToolExecutor.execute` on an explicitly synthetic reserved `.invalid` target with a completely inert registered in-memory handler and disposable SQLite evidence ledger. No network, DNS, target-capable adapter, live grant issuance, scanners, customer data, external AI, real remediation/retest or deployed behavior.

Nine tests:

- **Five deliberately unresolved `unittest.expectedFailure` RED**: postconstructor replacement with allow-all duck, replacement with `ExecutionPolicy` subclass, `object.__setattr__` rewrite, `__dict__` shadow and attribute deletion. A replacement must be rejected or ignored **without changing the original policy identity**. An otherwise out-of-scope TARGET_ACTIVE call must still be denied, with zero handler calls and zero evidence writes.
- **Four ordinary controls**: trusted policy out-of-scope refusal, same trusted policy allows in-scope synthetic low-risk control, missing grant denial, passive mode cannot invoke an active tool even if a grant exists.

The expected REDs represent **real unresolved source-owner admission gaps**, not tests that have already fixed the implementation. Even a hosted green summary including `expected failures=5` cannot be interpreted as authorization readiness.

## Source-owner closure

1. Original #107 owner binds the exact constructor-selected policy identity throughout the executor's lifetime; do not use any later public/shadowed policy object for an actual dispatch.
2. Original #100/#779/#935 owners retain constructor and policy object contracts. No concurrent owner source changes here.
3. Convert all five REDs to ordinary PASS and preserve unmodified canonical/risk/mode/scope/tenant/capability controls; zero side effects on any forbidden rewrite.
4. Exact-final-head hosted Python 3.11/3.14 plus independent permanent registered VPS runner, current-main compatibility, source-owner and independent security/privacy review plus explicit human authorization before merge/deploy.

Tests do not claim immunity to unrestricted Python introspection or malicious code execution in-process.
