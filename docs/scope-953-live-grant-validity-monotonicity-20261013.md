# Scope #953 — Temporal monotonicity at live authorization revalidation

**Phase:** INCUBATE M3/M7 — offline PLAN/LAB ONLY. **DRAFT/HOLD, NO MERGE, NO DEPLOY.**

## Independent acceptance scope

This branch is deliberately based on exact frozen source-owner PR #107 commit `c37ee27d922a7dd400eee1db39268f4a6269e431`. Only **new tests and documentation** are permitted. Source owner PR #107 retains `ToolExecutor`, `DomainStore` and integration ownership. Scope/capability/risk monotonicity belongs to issue #951, not #953.

The immutable `RunContext.authorization` represents the most authority the run can ever carry. During live resolution the same persisted grant ID is not sufficient to establish **temporal** monotonicity. Let the original window be `[S_from, S_until]` and the newly resolved live grant window be `[L_from, L_until]`, with aware UTC-compatible instants. An existing run must be rejected on **any** temporal broadening:

- `L_from < S_from`, even when both windows currently contain now.
- `L_until > S_until`, even when both windows currently contain now.
- An expired original snapshot must never be revived by extending live expiry.
- A future-dated original snapshot must never be activated early.
- A live window narrowed within the original snapshot is acceptable only when the *existing* policy, grant identity, current-time and all other authorization checks still allow it.
- Neither immutable input grant may be changed and every rejection must happen *before* handler invocation and evidence persistence.

## Implemented evidence

New `tests/test_scope_953_live_window_monotonicity_red_20261013.py` drives the **real PR #107 `ToolExecutor.execute`** through a registered `TARGET_ACTIVE` test tool, using only a synthetic `.invalid` asset and an inert handler. All test evidence is written to disposable local SQLite via `StateStore`. No DNS, sockets, HTTP, scans, customer data, real target capability, grant issuance or deployment exists in the test.

Four deliberately unresolved `unittest.expectedFailure` methods pin the original bug at the real executor boundary: expired revival, future activation, and widening of either side of an already-current interval. Six ordinary positive/negative controls prove unchanged equal/narrow-current dispatch, narrow-expired/future denial, missing live authorization and different-grant ID denial. Denial checks require no handler call, no new evidence row, and original grants intact. **Expected failure is not a security fix.** The source-owner integration must convert all four to ordinary PASS; avoid masking regression with permanent XFAIL.

## Owner handoff / gates

1. PR #107 owner adds an atomic, fail-closed same-grant temporal comparison *in addition to* current-time live validation, identity, assets/capabilities/risk and actual grant revocation.
2. Invalid or naive datetime values must be rejected safely; datetime-type issues #647/#738 own separate type admission.
3. Owner converts all four RED tests into ordinary PASS and exercises actual real executor with synthetic controlled clock/time edges.
4. Re-run exact-final-SHA GitHub-hosted Python 3.11 and 3.14 **plus separately registered permanent VPS** CI, latest-main composition, independent scope/security review and explicit human approval.
5. Never merge, wire production, dispatch a target-capable adapter, scan or deploy from this DRAFT.

Issue: https://github.com/Zennay/Lightup/issues/953

Base source-owner PR: https://github.com/Zennay/Lightup/pull/107
