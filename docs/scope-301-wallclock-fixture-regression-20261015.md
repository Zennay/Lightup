# Scope #301 — real-clock fixture regression repair (2026-10-15)

## Failure reproduced from existing source

`tests/test_scope_legacy_falsy_window_301_red_20261014.py` defines
`NOW = 2026-10-14T12:00:00Z` as a stable, explicit clock for direct
`Authorization.is_current(NOW)` assertions. That is appropriate for
boundary/inclusive tests.

One *ordinary passing* immutability test did something different: it
constructed an authorization valid from `NOW - 1 day` until
`NOW + 1 day`, and then called `ScopePolicy.decide()`. This path invokes
`Authorization.is_current()` **without an explicit clock**. After
`2026-10-15T12:00:00Z`, the stored authorization is genuinely expired,
so the normal immutability test fails for a correct authorization denial.

## Isolated change

- Keep `NOW` fixed for explicit-clock unit/temporal boundary tests.
- Use an aware UTC wall-clock snapshot when creating windows passed into
  `ScopePolicy.decide()`, which itself uses a wall-clock evaluation.
- The positive immutability case has a one-day validity cushion around
  evaluation time; the new negative case has an expired window ending
  a full day before evaluation and proves the same record is unchanged.
- Require `AUTHORIZATION_EXPIRED` for the negative, and maintain
  `allowed=True` only for the synthetic in-scope, structurally valid
  legacy authorization in the existing positive test.
- All existing deliberately `expectedFailure` #301 tests remain exactly
  as they were. In particular, falsey temporal bounds remain an open
  **production source defect**; this change does *not* solve it.

## Hermetic clock-edge regression (W2)

The installed production `ScopePolicy.decide(Target(...))` is called under a
test-local patch of the `lightup.models.datetime.now(timezone.utc)` provider.
The test checks **five exact instants** against one immutable fictional
authorization: one microsecond before `valid_from`, exactly at `valid_from`,
inside the validity interval, exactly at `valid_until`, and one microsecond
after `valid_until`. This ensures both inclusive edges and strict outside
denials. Each case requires the correct `ScopeReason`, exact normalized host,
exact timezone-aware clock invocation, and an unmodified authorization object.

Unlike an ordinary wall-clock snapshot, this regression executes deterministically
on every calendar date, including beyond October 2026. It exercises the real
scope-to-legacy-authorization path without modifying production clock injection
or relaxing any of the existing expected-RED source security canaries.

## Ownership and proof gates

Only this original time-window test module and this standalone explanation
are modified/added. No `src/`, CI/workflows, runners, other worker
branches, installed grant verification, lab execution or real targets.

Before promotion, confirm the *exact commit* in hosted Python 3.11/3.14
unit + real producer integration jobs and separately on the permanent,
registered `vps-bb300bba` runner. A green hosted run alone does not
demonstrate permanent VPS verification, customer consent, identity,
revocation, security/privacy review, or permission to scan.

**LightUp INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD.**
No merge, deployment, grant issuance, adapter dispatch, or active target scan
without independent ownership review and human approval.
