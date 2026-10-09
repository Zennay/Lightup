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
