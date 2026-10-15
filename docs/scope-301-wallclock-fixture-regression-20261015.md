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
test-local explicit-time delegation to the actual installed `Authorization.is_current` method.
The test checks **five exact instants** against one immutable fictional
authorization: one microsecond before `valid_from`, exactly at `valid_from`,
inside the validity interval, exactly at `valid_until`, and one microsecond
after `valid_until`. This ensures both inclusive edges and strict outside
denials. Each case requires the correct `ScopeReason`, exact normalized host,
one call to the exact installed authorization method with a timezone-aware evaluation instant, and an unmodified authorization object.

Unlike an ordinary wall-clock snapshot, this regression executes deterministically
on every calendar date, including beyond October 2026. It exercises the real
scope-to-legacy-authorization path without replacing the runtime datetime symbol
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
instant** (the real `Authorization.is_current` is called with explicit `now`). The production logic
continues to be executed unmodified, including the actual legacy
`Authorization.is_current()`. Assertions verify the installed method receives the
aware evaluation instant, a positive in-window `EXPLICIT_HOST`, an expired
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

## Reference repair mutation witness (W9)

A dedicated ordinary-PASS acceptance method runs the four W7/W8
**intentional source-RED** test methods through normal `unittest.TestCase.run`
while applying a **test-local monkeypatch** to the legacy
`Authorization.is_current()` implementation. The toy reference repair
rejects any present `valid_from` or `valid_until` that is not an exact
built-in aware `datetime`. All four real-source REDs must flip to
`unexpectedSuccess` (that is, their assertions now pass); no errors,
ordinary failures or lingering expected failures may be hidden. A real
canonical timezone-aware authorization remains allowed on the existing
installed scope route under that same reference narrowing.

This checks that the W7/W8 tests will reveal a successful *class of source
repair* rather than stay eternally green merely because they are decorated
with `expectedFailure`. The monkeypatch is installed **only in this
single synthetic test process**, and is automatically reverted. It is
**not a production implementation** and makes no statement about durable
operator consent, revocation, ingestion, egress or current live grants.

## Early-denial clock contract fix (W10)

The first W9 hosted run on SHA `d611bb3...` correctly identified a
**test-harness** mistake, unrelated to production behavior: the synthetic
reference type guard denies malformed date inputs *before* calling
`datetime.now()`, but the test helper previously required a clock read in
all cases. Both Python unit jobs observed two W9 witness assertions failing
(the two real public-scope REDs); producer integrations were skipped.

The W10 version of the helper permitted **zero mocked clock reads only for
explicit malformed-grant denial**. W14 replaces that mechanism with an
explicit-time delegation wrapper: normal decisions call the exact
authorization record's real installed `is_current` once. Explicit early
denial may omit that call only in the narrowly marked malformed cases.
The `datetime` class itself is no longer replaced.
This preserves and strengthens the intended monotonic fail-closed
contract: rejecting malformed authorization *before* time evaluation is a
legitimate safe implementation. It does not authorize any real target,
issue a durable grant, or fix installed production source.

## Full fourteen-RED repair witness (W11)

The synthetic-only reference type guard is now checked against **all 14
original or newly added #301 malformed temporal boundary RED methods**:
eight scalar falsey start/end cases (`0`, `False`, empty string and empty
tuple), two actual public-scope falsy-value admissions, two deceptive
`datetime`-subclass direct currency-window admissions, and two additional
real `ScopePolicy.decide()` subclass-scope admissions.

Every underlying method must turn from an installed-source
`expectedFailure` into an explicit `unexpectedSuccess` under the same
in-memory exact-aware-datetime-or-None reference narrowing, with **no**
unexpected errors, ordinary failures or lingering expected failures.
A canonical aware built-in datetime window still admits the explicitly
declared fictional host through real installed scope code. This tightens
the source owner's eventual repair acceptance without claiming the
temporary test-local patch has been integrated or provides real consent.

## Concrete source-ALLOW proof, not exception-masked RED (W12)

In Python `@unittest.expectedFailure` can classify either an **assertion
failure** or an **unexpected exception** as an expected failure. Therefore,
the preceding fourteen intentionally expected-RED checks alone do not
prove that the source *actually authorized a forbidden target*: an unrelated
`TypeError`, `ValueError`, or an adapter/setup bug might count as RED.

Two new **ordinary PASS** checks demand positive proof against the actual,
currently installed source, without patching its authorization logic:

1. Ten deliberately malformed falsey start/end values (eight scalar field
   cases plus two malicious `datetime.__bool__` subclass cases) must return
   an actual `True` from `Authorization.is_current(NOW)`, and must not
   mutate their fictional grant. Any thrown exception fails the witness.
2. Four cases must return an actual `ScopeDecision(allowed=True,
   reason=EXPLICIT_HOST)` for a *fictional* explicitly declared public
   host: end `False`, end `0`, future falsey-datetime subclass, or expired
   falsey-datetime subclass. The real `ScopePolicy.decide` path runs under
   the same hermetic injected UTC test time and must not throw or mutate.

**Safety note:** these are deliberately **PASS observations of broken
installed source**, not passing security policy. Their expected outcome
must be revised/retired when source-owner #100/#104 properly denies all
malformed temporal fields. The intended strict behavior remains captured
by the separately expected-RED tests and the isolated narrowing witness.
The proof does not issue real consent, target network requests or scans.

## Naive and non-offset-aware boundary failure (W13)

The #301 required invariant also demands **exact timezone-aware** built-in
datetimes (or None). Simply checking `boundary.tzinfo is not None` is
insufficient: a `tzinfo` instance can return `None` from
`datetime.utcoffset()`, making the value effectively offset-naive.

A new **ordinary source characterisation** confirms the actual installed
code currently **raises TypeError** (instead of returning a fail-closed
`False` or a proper `ScopeDecision`) for four malformed clock bounds:
timezone-naive future-start/expired-end and pseudo-naive non-null
`tzinfo` future-start/expired-end. Each check verifies both direct legacy
`is_current` and the actual in-memory public-scope route. These exception
observations are not counted as successful authorisation decisions.

Six additional **intentionally expected-RED** tests require explicit
denials on these invalid fields (four direct and two public scope). As with
the original REDs, an exception can otherwise be counted as RED, so the
ordinary characterisation separately pins the **real exception cause**.

The **test-local hypothetical strict guard** now checks exact built-in
`datetime`, non-null `tzinfo`, **and non-null `utcoffset()`**. The
reference mutation witness requires **all twenty** installed #301
expected-RED methods to become `unexpectedSuccess` with no leftover
ordinary failures/errors. Canonical aware-datetime public scope remains
a positive control. This hypothetical guard is *not* production code.
Actual denial behavior, safe exception handling and owner-integrated
source validation are still to be implemented and reviewed.

## W14 — source-owner-compatible test clock injection

The original historical date-stability tests mocked
`lightup.models.datetime` to fake `datetime.now()`. That would cause a
**false CI failure** after a legitimate future #301 source fix: a
`type(valid_from) is datetime` comparison would see a mocked module
symbol instead of the actual builtin `datetime` class.

W14 now changes only the **test-owned temporal injection harness**.
Rather than replace `datetime`, it wraps `Authorization.is_current`
for one fictional scope evaluation and delegates to **the actual
installed implementation** with an explicit timezone-aware
evaluation instant. Source code, runtime clock class identity, and
canonical datetime comparisons remain untouched.

Every ordinary decision must evaluate the **exact same authorization
record once**. Unanticipated explicit times supplied by the scope layer
are rejected; an explicitly opted-in malformed-bound early DENY is
allowed to skip the call. The five exact microsecond boundaries, 642
shuffled synthetic clock instants and all other time tests use the
common helper. A new normal PASS regression directly asserts
`lightup.models.datetime is datetime` inside an actual `is_current`
execution, and asserts exact builtin datetime bounds on the fictional
canonical authorization.

These changes make the tests resilient to the eventual correctly
narrowed production datetime type contract. They grant no runtime
permission, edit no production file, and perform no network I/O.

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
