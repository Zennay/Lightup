# Issue #952 — compose ledger, resolver and monotonic live-grant narrowing

**LightUp posture: INCUBATE M3/M7; PLAN/LAB only. DRAFT/HOLD, NO MERGE, NO DEPLOY.**

## Parent and collision-free ownership

This is a new, independent **tests/docs-only** branch stacked directly on the original ToolExecutor source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107) exact unchanged parent `c37ee27d922a7dd400eee1db39268f4a6269e431`. It does not edit any existing production/source-owner files or other PR branches. Distinct from [#950](https://github.com/Zennay/Lightup/issues/950), which covers combined ledger+grant identity, this [#952](https://github.com/Zennay/Lightup/issues/952) adds live **scope monotonicity** on top.

Source-owner #107 retains all actual executor/live authorization writes. Original #948/#949/#951 contracts remain untouched; original StateStore, its #170 FK work, active executor v5, CI runners, web, domain, activation, target-capable workers and evidence-remediation are not changed.

## Composed fail-closed contract

A same-ID live grant can narrow but never widen the run's authorization snapshot. Both the ledger and the live revalidated grant must remain canonical, independently of live assets / excluded assets / capabilities / max risk.

- A new asset or capability in the live grant must not mint new authority.
- The live risk ceiling must not rise above the immutable run grant's ceiling.
- Previously excluded assets must not become allowed by removing the exclusion.
- A duck grant and fake evidence ledger combined must not bypass any of the above.
- Legitimate narrowing, expiry, missing or wrong grant ID and exact canonical successful evidence persistence must retain their original fail-closed semantics.

## Implemented offline executable gate

`tests/test_scope_952_monotonic_ledger_grant_composition_red_20261013.py` has **13** real in-process `ToolExecutor.execute` methods. Five are intentionally unresolved `unittest.expectedFailure` requirements for asset widening, capability widening, risk increase, removed exclusion and combined noncanonical grant/fake evidence ledger. Eight ordinary controls cover unchanged grant/evidence persistence, valid narrowing (allow and deny), missing/different/expired live authority. The tests use a disposable local SQLite file, reserved synthetic `.invalid` labels and an inert handler; **never** a network listener, DNS, external target or real scanning.

`expectedFailure` denotes a known unfixed security invariant, **not** a green security result. The source owner must turn RED into ordinary PASS, while keeping all mode/risk/tenant/engagement/scope/revocation checks and zero handler/evidence effects on denial.

## Release criteria

Only an original source-owner integrated fix reviewed by independent security/privacy/scope reviewers, exact-final-head Python 3.11/3.14 hosted unit and real-producer canaries, permanent `[self-hosted,zcloud,vps]` proof on that identical SHA, latest-main compositional verification and **explicit human approval** can promote this held work. No merge or deployment authorized.
