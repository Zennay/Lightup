# Scope #949 — Only exact live AuthorizationGrant objects are authoritative

**Release posture:** INCUBATE M3/M7 · PLAN/LAB ONLY; **DRAFT/HOLD, NO MERGE, NO DEPLOY**.

## Source-verified defect and boundary

Original source-owner [draft PR #107](https://github.com/Zennay/Lightup/pull/107) `ToolExecutor.execute` checks for a non-null resolved grant with the matching `grant_id`, but does **not** verify `type(resolved) is AuthorizationGrant` before constructing `ExecutionRequest` and calling `ExecutionPolicy.decide`. A duck-typed object or mutable subclass can impersonate an authoritative current grant, override `is_current`, or provide an unrelated scope. This is a synthetic offline **trust-boundary gap**, not evidence of a real exploit.

This acceptance pack is pinned directly to source-owner exact SHA `c37ee27d922a7dd400eee1db39268f4a6269e431`. It adds NEW tests/docs only. It does **not** modify source-owner #107, resolver lifecycle owner #938, scope monotonicity owner #951, temporal owner #953, grants, main or other workers' paths.

## Implemented regression contract

New `tests/test_scope_949_live_resolver_exact_grant_red_20261013.py` uses real `ToolExecutor.execute`, strict policy-call recorder, disposable local SQLite and an inert synthetic handler with a reserved `.invalid` asset. No model, sockets, DNS, HTTP, target activity, scanning, production data, issued grants or deployment.

Nine test methods:

- **Four intentional expected RED**: same-ID duck grant, canonical-field `AuthorizationGrant` subclass, expiry-overriding subclass, and duck with unauthorized expanded scope. All MUST reject **before `ExecutionPolicy.decide`** as well as before handler/evidence writes.
- **Five ordinary controls**: exact canonical same-ID object allowed, missing resolved grant rejected, different-grant-id rejected, exact expired resolved grant rejected by existing policy, exact wrong-client resolved grant rejected by existing policy.

An `OK (expected failures=4)` test run would still mean that four security invariants are violated. The REDs must become ordinary PASS after production owner code is changed.

## Owner work to close #949

1. Validate **exact class identity** of the untrusted resolver return before accessing grant IDs or passing it to any policy, handler or evidence write: `resolved is None` denies; `type(resolved) is not AuthorizationGrant` denies.
2. Compare exact original grant ID and preserve trusted tenant/engagement and validity checks; do not treat this type check as authentication or durable consent.
3. Convert the four RED acceptance methods to ordinary green after source-owner integration; confirm unchanged positive controls and no dispatch/evidence side effects on every denial.
4. Obtain exact SHA hosted Python 3.11/3.14, independently registered permanent VPS CI, latest-main composition, independent privacy/security review and explicit human authorization before release.

Issue: https://github.com/Zennay/Lightup/issues/949
