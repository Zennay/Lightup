# Scope #938 — Trustworthy ToolExecutor live resolver binding lifetime

**LightUp posture:** INCUBATE M3/M7; offline PLAN/LAB ONLY. **DRAFT/HOLD, NO MERGE, NO DEPLOY.**

## Finding and ownership

The source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107) introduces a required live `authorization_resolver` for TARGET_ACTIVE dispatch but stores the callable as a writable public instance attribute. A caller can replace or shadow it after construction with a stale-grant-returning lambda, bypassing the intended database-backed revocation check. Immutable grants and unchanged policy logic do not defend against changing the **authorization authority provider**.

This new tests/docs-only branch is pinned directly to frozen #107 head `c37ee27d922a7dd400eee1db39268f4a6269e431`. The original `ToolExecutor` and `DomainStore` are exclusively owned by #107. Separate #949 covers *resolver returned grant type*, #951 scope monotonicity and #953 validity interval monotonicity; none are edited by this branch.

## Test contract

New `tests/test_scope_938_resolver_lifetime_immutable_red_20261013.py` invokes the authentic PR #107 `ToolExecutor.execute` with synthetic context, a local disposable SQLite evidence ledger, registered inert in-memory handlers and reserved `.invalid` assets. No sockets, DNS, HTTP, scans, targets, actual grants, external AI or deployment.

Nine test methods include:

- Four deliberately unresolved `unittest.expectedFailure` REDs: direct public attribute replacement, `object.__setattr__` replacement, direct dictionary shadowing, and deleting original resolver binding. After any attempted mutation the exact configured resolver must remain authoritative. Rejected target-active calls must hit **zero handlers/evidence writes**.
- Five ordinary positive/negative controls: original revoked resolver denies; missing resolver denies; original live resolver permits only a synthetic control; passive mode does not consult or bypass active authority; lab mode stays lab-only and cannot invoke target-active tool.

A report of `OK (expected failures=4)` means known in-process authorization defects remain unresolved, not that binding is immutable.

## Owner acceptance

Source-owner #107 must make the construction-time trusted resolver unreplaceable/unshadowable for the entire executor lifetime, not merely privatize a writable attribute. Real dispatch should use that pinned identity, or fail closed. Keep existing revocation, tenant/grant identity, risk and mode checks; convert four REDs to ordinary PASS. Check tested approaches for alternative introspection or mutable closure state; this test pack does not prove resistance to arbitrary Python reflection.

Exact-final head hosted Python 3.11/3.14, independently registered permanent VPS CI, original owner review, latest-main composition, privacy/security and explicit human release approval are mandatory. No production wiring/merge/deploy or active target interaction from this branch.

Issue: https://github.com/Zennay/Lightup/issues/938
