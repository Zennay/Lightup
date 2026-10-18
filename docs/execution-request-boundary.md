# ExecutionPolicy source boundary — independent integration candidate

**Project phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.

## Product behavior

The original `ExecutionPolicy.decide()` previously fell through to real-target authorization logic for unknown or string-like interaction values. Untrusted annotation-only request fields also permitted polymorphic values and nonboolean lab markers. The updated policy refuses noncanonical request identities **before evaluating any authorization**, distinguishes all four exact interaction modes and denies unknown modes without calling a grant or handler.

A direct TARGET_ACTIVE request additionally requires a canonical in-memory grant, built-in timezone-aware UTC-comparable validity windows, immutable-shaped scope field tuples and exact RiskLevel. Only real-target mode consults the stored in-memory grant. It retains denial for expired grants, asset exclusions, capabilities outside scope, destructive-on-target and lab-to-target crossings.

**The default remains fail-closed:** malformed claims yield a negative PolicyDecision, not implicit approval; no network or execution starts inside the policy.

## What this change cannot prove

These source gates are **not** authenticated, durable grant verification; they do not prove actual client or operator consent, tenant lineage, original request approval, action-time revocation or scope record integrity at storage time. They are intentionally separate from the active owner branches #107/#163, domain owner #1570 and source/grant work #177/#673/#829. Future workers must continue to enforce their actual execution-time checks.

Only `src/lightup/execution_policy.py` and this independent documentation are modified. No QA/regression/testsuites, no live targets, network, scanner, grants, runner actions or workflow modifications. Syntactic source/build inspection is not a security signoff. Required original exact-head hosted CI and registered permanent named VPS runner, security/privacy review and explicit HUMAN GO remain mandatory before any merge or deployment.

## Original grant/scope source stability

The decision path now first accepts exact canonical original grant/scope values, then constructs a detached in-memory builtin snapshot of the original grant and scope. Asset, capability, risk and validity checks read the snapshot rather than repeatedly reading caller-owned objects. Before a positive decision, both original object identities and their canonical fields are compared again; changed sources produce a negative decision. This reduces in-process read drift but cannot prove a live durable grant, stop all simultaneous mutation or replace revocation-at-dispatch.
