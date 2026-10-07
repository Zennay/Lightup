# Scope authorization: evaluation-time type acceptance (#403)

## Boundary

This acceptance slice is stacked on exact draft PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`. It does not modify the
active legacy-authorization source owner.

## Required invariant

`Authorization.is_current(now=...)` must distinguish omission from malformed input:

- only `now=None` may select the current UTC wall clock;
- every explicitly supplied evaluation instant must be a `datetime`;
- supplied datetimes must remain timezone-aware;
- canonical aware datetimes keep the existing inclusive window semantics;
- malformed caller input fails closed as a controlled `ValueError`;
- no falsey value may erase itself by falling through `now = now or ...`.

The regression covers the silent falsey cases `False`, `0`, and `""`,
plus truthy non-datetime controls so the eventual source repair establishes the
full runtime type boundary rather than only special-casing falsey values.

## Expected pre-fix state

The canonical controls are green. The five malformed-clock cases are expected
RED against the pinned #100 source owner:

- falsey values are currently replaced with wall-clock time;
- truthy non-datetime values currently escape through incidental attribute/type
  errors instead of a controlled authorization-boundary rejection.

## Collision and safety

Changed paths are limited to this document and
`tests/test_scope_authorization_falsy_evaluation_time.py`.

No production source, target interaction, DNS/network I/O, capability
execution, deployment, remediation/retest execution, verdict creation, or
attack-path mutation is part of this acceptance slice. Source repair remains
with PR #100's legacy Authorization owner.
