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
