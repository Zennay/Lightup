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
