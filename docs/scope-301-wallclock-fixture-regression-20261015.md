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

## Final fixture-path closure (W5)

The earlier ordinary `test_canonical_expired_explicit_host_scope_denied`
also used implicit host wall-clock time, even though its historical window
was far past the current date. It now exercises the same installed source
with the exact frozen `NOW` via the hermetic helper. This closes the last
ordinary PASS test in this #301 module that implicitly depended on a
machine calendar. The existing intentionally expected-RED malformed-bound
tests are unchanged, and source owner #100/#104 still owns actual repair.

## Cross-century and cross-grant acceptance (W6)

Two additional real installed-source ordinary regressions close remaining temporal
reference risks without modifying application code:

- **45 fixed synthetic time observations across 2024, 2026, 2030, 2050 and
  2099:** 25 true-instant-equivalent observations in UTC or canonical fixed
  offsets from UTC-11 through UTC+14, plus 20 inclusive/start-end/outside
  window boundaries. The evaluator must preserve the same positive/negative
  membership regardless of calendar year, timezone offset and local date.
- **360 seeded, shuffled synthetic decisions across five distinct Authorization
  instances and nine evaluation dates** prove that an earlier authorization's
  in-window result does not confer implicit authority to a different expired
  or future-dated authorization. Every record's contents remain unchanged.
  No cached grant, live consent, target I/O or dispatcher is involved.

## Polymorphic falsy date-source acceptance (W7)

The legacy `Authorization.is_current()` performs truthiness tests on the
optional start/end fields before comparing against `now`. An adversarial
`datetime` subclass can override `__bool__` to return `False` while
carrying an actually future start or expired end; current production source
incorrectly treats both as unbounded and returns current. Two new **genuine
intentional expected-RED** tests demonstrate this on the installed source.

This is a *known unresolved security invariant*, **not** a successful
hardening of runtime authorization. The #100/#104 source owner must require
canonical exact built-in aware datetimes or None, and then convert these
expected-RED tests to ordinary PASS after production repair. The two RED
regressions must never be interpreted as consent or release evidence.

## Real public-scope effect of malformed datetime (W8)

The previously documented W7 source-REDs exercised
`Authorization.is_current()` directly. W8 adds **two more intentionally
expected-RED tests against the actual installed
`ScopePolicy.decide(Target(...))` path** on a fictional explicitly declared
`scope.fixture.example.test` host.

At a frozen UTC evaluation instant, a `datetime` subclass with a lying,
false-valued `__bool__` carries (a) a future authorization start or (b) a
past authorization expiry. The legacy code currently skips both fields and
the public scope gate incorrectly permits that in-memory fictional host.
Each test verifies normalized host identity and immutable synthetic grant
before requiring a DENY that current source fails to supply. No DNS,
network, handler, customer request, real grant or active adapter is used.

These are not ordinary green security controls; their expected-RED status
means the actual public-scope boundary is **still vulnerable to type
confusion**. On source-owner repair, both must become ordinary PASS,
together with the earlier direct `is_current()` REDs, without weakening
canonical inclusive datetime semantics.

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
