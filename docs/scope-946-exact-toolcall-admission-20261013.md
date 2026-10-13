# Scope #946 — exact ToolCall admission before registry/argument parsing

**Posture:** LightUp INCUBATE M3/M7 — offline PLAN/LAB ONLY. **DRAFT/HOLD, NO MERGE, NO DEPLOY.**

## Verified source boundary
`ToolExecutor.execute` on original source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107), frozen `c37ee27d922a7dd400eee1db39268f4a6269e431`, directly calls `call.tool_id` and `call.arguments_dict()` before establishing the exact `ToolCall` class. A duck object or `ToolCall` subclass can therefore run caller-owned getters and extraction code at the authorization boundary. This is an **offline type/dispatch integrity issue**, not a claim of a live target exploit.

This additive tests/docs-only branch is scoped to [issue #946](https://github.com/Zennay/Lightup/issues/946). It leaves the original ToolExecutor, canonical `ToolRegistry` schema owner #156, field-level `ToolCall` argument/asset validation, all other workers' branches, main, and deployment unchanged. The separate composition #947 is not edited.

## Implemented tests
New `tests/test_scope_946_exact_toolcall_red_20261013.py` uses the **real PR #107 executor**, synthetic local-only `ANALYSIS` tool, disposable SQLite `StateStore`, inert no-network handler, reserved `.invalid` asset. Nine methods:

- **Four deliberately unresolved `unittest.expectedFailure` RED:** duck outer ToolCall, subclass outer ToolCall, subclass overriding `arguments_dict()`, and throwing canary getter. Denial must happen **before ToolRegistry.get**, any argument extraction/getter, handler invocation or evidence persistence.
- **Five ordinary positive/negative controls:** canonical exact call with typed arguments succeeds and stores test evidence; exact unknown tool, missing required argument, invalid argument type, and unknown tool with supplied argument refuse before handler/evidence.
- Never treat `OK (expected failures=4)` as security readiness. Convert expected RED to ordinary PASS only after original owner fix.

## Original owner closure
Require `type(call) is ToolCall` at the very beginning of `ToolExecutor.execute`, before registry lookup or any untrusted property access, without weakening mode/risk/grant/tenant/ledger checks. Original source owner #107 must integrate, run exact-final-head hosted Python3.11/3.14 plus separately registered permanent VPS, latest-main composition and independent security/privacy + explicit human release. No real targets, network, scanning, grants, deployment or merge from this DRAFT.
