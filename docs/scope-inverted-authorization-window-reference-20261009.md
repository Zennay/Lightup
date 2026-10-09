# Authorization window boundary — isolated offline regression

This branch characterizes existing `Authorization.is_current` and `ScopePolicy.decide` behavior for inverted, inclusive, and just-outside time windows. It contains no production code or authorization activation.

## Expected results
- Inverted start/end cannot be current at representative before/during/after instants.
- A correctly ordered window includes its exact endpoints and excludes instants just outside them.
- A synthetic grant cannot authorize an unlisted public host; a missing grant denies an allowlisted public host.
- Naive caller-supplied timestamps raise `ValueError`.
- A zero-length window is current at exactly one instant and not a microsecond before/after.
- Equivalent aware timestamps expressed using different UTC offsets yield the same validity result.
- Inverted windows remain invalid even when endpoints use different offsets.
- A public target with an authorization window beginning tomorrow is denied today.

## Run
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_inverted_window_reference_20261009.py' -v`

## Boundary and review
Fixtures are fabricated and do not establish issuer identity, cryptographic integrity, approval, tenant binding, scope ownership, or dispatch-time consent. Passing tests do not license scanning. No target network traffic, DNS resolution, active assessment, deployments, or production executor modifications. Keep the PR draft pending exact-head hosted checks, canonical permanent VPS CI, and scope-owner review. This is additive coverage and must not overlap ongoing runtime enforcement work.

## Observed malformed stored timestamp gap
Three additional characterization controls document current behavior (not desired release behavior): naive `valid_from` / `valid_until` values raise `TypeError` when compared with UTC-aware `now`, including through the public-host `ScopePolicy.decide` route. A future production pre-I/O gate must catch malformed persisted authorization and return a deterministic denial before dispatch. These tests intentionally assert existing exceptions, **not** an approved fail-closed implementation. Production owner must decide repair and add negative acceptance tests without broadening authority. Related pending boundary suites (#999 and #1058) remain separate.

## Open-ended legacy windows
A start-only window permits all later instants; an end-only window permits earlier instants; a grant with both bounds absent returns `is_current=True` for any aware supplied time. This is a description of the legacy dataclass's temporal predicate only, never authenticated issuer approval. Production execution must require durable, issuer-verified consent and separate pre-dispatch checks; this reference does not authorize an unbounded grant or change behavior.

## Unparsed persisted strings
Three isolated controls also show that raw string values in `valid_from` or `valid_until` raise `TypeError` in the legacy temporal evaluator; the public-host scope path similarly propagates the error. This is characterization of the defect, not a desired behavior. Persisted timestamps must be parsed and validated by their source owner before an enforcement decision; errors must fail closed without initiating I/O. These fixtures never grant actual authority.

## Denial ordering controls
An out-of-scope public hostname is rejected before attempting to interpret a malformed grant window. Likewise, an allowlisted public hostname without a grant returns `AUTHORIZATION_MISSING` regardless of URL path. Both checks are offline and constrain the regression surface for future production fail-closed repairs. They do not verify signed consent or authorize target execution.

## Additional malformed-value finding
Truthy non-datetime bounds (such as `True` and integer `42`) raise `TypeError`. More importantly, falsy malformed bounds (`0`, `False`, `""`) bypass the legacy `if self.valid_from` / `if self.valid_until` guards and are treated as absent, returning `is_current=True` for a synthetic unbounded grant. Neither behavior is acceptable evidence of authenticated permission. Production owner should require `datetime`-typed timezone-aware bounds or a separately reviewed strict schema, reject all malformed values before pre-I/O policy evaluation, and test denial explicitly. These tests characterize legacy defects and do not activate real targets.

## Confirmed policy-level impact (synthetic fixtures only)
Three new regression methods verify the actual legacy `ScopePolicy.decide` result, not merely `Authorization.is_current`: an explicit allowlisted public hostname paired with a falsy malformed start (`False`) or end (`""`) yields `allowed=True` and `EXPLICIT_HOST`; an unlisted hostname still returns `OUT_OF_SCOPE`. This is a narrower, concrete policy-level bypass of time validation, **not evidence of real-world scanner execution** or authenticated consent. The production source owner should reject non-`datetime` stored bounds before scope evaluation, including falsy values, and protect all pre-I/O authorization paths with deny-by-default behavior. No production code is changed here.

## Complete falsy-bound public-host matrix
The offline reference now checks all six combinations of `0`, `False`, and empty string appearing as either start or end of a synthetic grant against an explicitly allowlisted host. All currently yield `EXPLICIT_HOST` under legacy `ScopePolicy`. Parallel controls confirm none of these values can override the host allowlist. This exposes a narrow legacy temporal-validation weakness, not authenticated approval or a production dispatch bypass. Reject malformed values explicitly in the production owner's pre-I/O gate.

## Production repair acceptance handoff — issue #1128

Implementation belongs to the production enforcement owner (#107), not this test branch. Before changing execution permission, the owner must establish a trusted source of grant records and explicit issuer verification. No legacy `Authorization.is_current()` success may be interpreted as permission to dispatch.

| Input / condition | Required executable result | Regression oracle |
| --- | --- | --- |
| `valid_from` or `valid_until` is `0`, `False`, or empty string | Deny with stable invalid-grant reason, no exception escape and no I/O | Legacy characterization matrix in this PR; new production tests must assert denial |
| Stored bound is string, integer, boolean, or naive datetime | Deny before scope execution | Malformed-bound cases |
| Both dates are aware but reversed or have an invalid interval | Deny without touching target | Inverted-window cases |
| Timestamp comparison or persistence decode fails | Deny deterministically; never default to unbounded | Exception characterization |
| Public host is not explicitly listed | Deny regardless of claimed grant | Existing out-of-scope controls |
| Grant absent, revoked, outside live window, or lacks issuer/tenant/asset/capability binding | Deny before any I/O | Owner-owned persisted-grant and dispatch-time acceptance |
| Fully authenticated in-scope grant with reviewed allowable capability | Eligibility only until exact dispatch-time gate succeeds | Owner-owned positive synthetic control; no live targets |

**Do not blindly change end-boundary semantics.** The legacy dataclass treats `valid_until` as inclusive, while related approval-window PRs may use exclusive expiry. The owner must specify the executable contract and migrate callers without accidentally widening authorization.

Review gates: pin implementation head; run focused failing-then-passing production acceptance, hosted Python 3.11/3.14, permanent VPS CI on that exact head; review overlap with #999, #1058 and #1125; obtain owner approval. No deploy or real-target activation is authorized by this handoff. Tracking: https://github.com/Zennay/Lightup/issues/1128.

## Strict-window offline reference (separate from production)

`tests/test_scope_strict_window_reference_20261009.py` adds nine isolated reference tests for a pure fail-closed temporal predicate. This is a proposed **temporal eligibility** contract only, not verified authorization. It denies unbounded windows, wrong types (including all falsy malformed values), naive clocks, invalid intervals, and clock-boundary overflow. For this reference the end is exclusive, deliberately contrasting with the existing inclusive `Authorization.is_current` semantics. Production owner must choose the correct migration contract for each grant type; do not transplant this predicate blindly.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_strict_window_reference_20261009.py' -v`.

The strict reference cannot authenticate issuer, owner, tenant, capability, revocation, persisted integrity or request intent. It must never be called as a stand-alone permission to scan. Production repair is tracked in #1128 under the #107 owner's surface.

## Reference clock robustness
Two additional strict-reference tests reject a timezone provider raising during `now.utcoffset()` and reject `datetime` subclasses masquerading as canonical instant values. The pure temporal predicate now returns `False` for malformed clock metadata rather than propagating that exception. This hardens only the offline reference, not the production executor or real-target permission validation.

## Repeated-hour DST ordering correction
The pure strict reference now normalizes all validated aware instants to UTC before comparing them. Python datetime comparisons between values sharing a `tzinfo` can otherwise use local wall-time order and miss the distinction between the first and second occurrence of a repeated clock hour (`fold=0` vs `fold=1`). The new test verifies start-inclusive/end-exclusive semantics across that boundary. This change is limited to the isolated reference and does not alter real-target execution policy.

## UTC boundary overflow controls
Two additional strict-reference tests cover conversion of extreme timezone-aware values that underflow UTC and equivalent instants expressed with different fixed offsets near expiry. UTC conversion overflow must produce `False`, never an exception or permission. Expiry stays exclusive in this isolated reference. These are temporal-only controls without issuer authentication or dispatch authority.

## Clock and expiry UTC overflow
The strict offline reference now includes both extreme `now` and `valid_until` values whose UTC conversion overflows. As with an overflowing start bound, temporal eligibility must be `False` without an exception escaping. All three paths remain synthetic and purely local; no validated issuer consent or execution rights are implied.

## Public-network temporal validation evidence
The legacy-falsy-bound defect also affects the `ScopePolicy` explicit **public network** branch, independently of explicit host names. New offline regressions characterize a synthetic `8.8.8.0/24` allowlist with `8.8.8.8`: a falsy corrupt start may produce `EXPLICIT_NETWORK`; an unlisted address `1.1.1.1` stays out of scope. Neither fixture makes a network request or grants authenticated permission. Production owner must cover both `EXPLICIT_HOST` and `EXPLICIT_NETWORK` in issue #1128's fail-closed acceptance.

## Public network denial and exception distinction
Two additional legacy policy tests confirm that an allowlisted public IP with **no grant** returns `AUTHORIZATION_MISSING`, while a truthy malformed stored start timestamp currently propagates a `TypeError` instead of delivering a typed denial. Combined with the falsy-corrupt public-network tests, this documents three separate codepaths the owner must reconcile under fail-closed execution semantics. The assertions are characterization only and do not approve dispatch.

## Public IP expiry asymmetry
The explicit public-network route now has isolated start **and** end timestamp characterization. A falsy corrupt `valid_until` (`0`, `False`, empty string) is silently skipped and currently yields `EXPLICIT_NETWORK`; a truthy malformed expiry produces `TypeError`. Both outcomes are unsafe as production permission evidence. The owner of issue #1128 must reject both malformed types as a non-executable denial, including at pre-dispatch revalidation. No target I/O is performed by these tests.

## Missing authorization provenance on the legacy allowlist gate
Two new offline controls demonstrate that a synthetic `Authorization(owner="", reference="")` with unbounded times still reaches `EXPLICIT_HOST` and `EXPLICIT_NETWORK` for explicitly allowlisted public targets. This is not trusted consent: `Authorization.is_current()` only evaluates time, not owner, issuer signature, grant authenticity, tenant, capability or revocation. Production issue #1128 requires a verified, durable grant at dispatch and a fail-closed denial for absent or unverified provenance, regardless of legacy policy output. No network I/O, approvals or production changes are included.

## Partial owner/reference metadata is not issuer verification
Two more offline characterization controls demonstrate that a merely nonempty `reference` cannot compensate for empty `owner`, and a nonempty `owner` cannot compensate for empty `reference` on synthetic public allowlist entries. Both paths may report legacy scope allow, but neither establishes authenticated consent, durable issuer proof or executable capability. Production gate owner must reject untrusted/missing provenance regardless of temporal scope outcome.

## Fixed UTC boundary truth matrix
The pure strict temporal reference now checks 21 combinations: seven instants surrounding the `[start,end)` window expressed with three timezone offsets. Every case must match UTC chronological eligibility, independent of wall-clock representation; the exact end remains excluded. This is only a temporal reference, not an authenticated authorization or executor gate.

## Untrusted timezone callback errors
The offline strict reference now treats ordinary `Exception` subclasses from timezone metadata and UTC conversion as temporal rejection rather than escaping the validation boundary. A custom `tzinfo` raising `RuntimeError` is exercised at start, expiry and current-clock positions; `BaseException` process interrupts are intentionally not swallowed. This reference does not issue consent or change production behavior.

## Follow-up correction: exceptions in all three temporal phases
Review of the earlier timezone hardening identified two remaining narrow `except (TypeError, ValueError, OverflowError)` handlers on stored start/end validation and UTC conversion. The first guard on the current-clock offset had already been expanded, but `RuntimeError` could still escape from the other two paths. Updated the isolated reference so all three phases catch ordinary `Exception` and deny safely while still propagating `BaseException` process interrupts. The existing three-position crashing timezone regression now covers the complete correction; this is not a production fix or grant authority.

## Timezone metadata mutation between validation and conversion
A further offline strict-reference regression uses a `tzinfo` implementation that returns a valid offset on first inspection, then raises a `RuntimeError` on conversion. It checks start, end and current-clock locations and requires denial without an exception escape. This models a changing/untrusted timezone provider; it does not validate a real issuer, dispatch or network action.

## Explicit red safety contracts (expectedFailure pending production fix)
Two new `@unittest.expectedFailure` checks assert the **desired** denied decision for a corrupt falsy start on a public allowlisted hostname and a corrupt falsy end on a public allowlisted IP network. Existing legacy implementation is known to return allowed, so these are marked expected failures: an overall green unittest run must **not** be mistaken for a repaired production gate. Once #1128's strict denial is implemented, expected successes (XPASS) require owner coordination to remove `expectedFailure` and retire or migrate the earlier bug-characterization assertions, before merge. No target I/O.
