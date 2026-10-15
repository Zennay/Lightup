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

## Chronological cache/replay regression (W3)

The same immutable fictional authorization is reevaluated at **642 seeded,
shuffled synthetic clock instants**, spanning two minutes before and after its
one-minute inclusive authorization window. The actual installed
`ScopePolicy.decide()` path must recheck current validity for **every**
decision, including after a prior in-window allowance. An out-of-window
decision must remain `AUTHORIZATION_EXPIRED`, not reuse any prior
`EXPLICIT_HOST` conclusion. The exact normalized host and original grant
remain unchanged. Tests use local in-memory clock substitution only, with
zero sleep, target I/O, cache store, customer approval or authorization issuance.

This is specifically a temporal non-caching regression for the #301
fixture route, **not** a claim that a mutable/cache-backed production runtime
has been secured. The separate run/executor revocation and concurrency
source owners keep their implementation responsibility.

## Fully hermetic ordinary PASS fixtures (W4)

The original normal immutability assertion and the new expired-window
immutability control are no longer tied even to a moving real-time window
with a generous margin. Both now evaluate the installed
`ScopePolicy.decide(Target(...))` through a **test-local frozen evaluation
clock** (`lightup.models.datetime.now(timezone.utc)`). The production logic
continues to be executed unmodified, including the actual legacy
`Authorization.is_current()`. Assertions verify the provider receives the
aware UTC timezone, a positive in-window `EXPLICIT_HOST`, an expired
`AUTHORIZATION_EXPIRED`, and identical before/after authorization records.

This removes the *entire real-calendar dependency* of these ordinary PASS
controls, including machine-clock drift or test suites running years after
the historical 2026-10-14 constant. It does not confer consent or alter the
ten existing intentional #301 RED checks for malformed falsey validity
boundaries.

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
