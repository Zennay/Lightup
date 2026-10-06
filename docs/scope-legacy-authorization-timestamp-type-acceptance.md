# Scope authorization: legacy Authorization timestamp type acceptance

Issue: #301

This tests/docs-only contract is stacked on exact PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

`Authorization.valid_from` and `valid_until` must be either timezone-aware
`datetime` values or `None`. Falsy non-datetime values must never erase a
not-before or expiry boundary through Python truthiness.

The acceptance covers `0`, `False`, and `""` independently on both
temporal fields. A future fix may reject at construction or during
`is_current()`; either is acceptable, but treating the authorization as
current is not.

A canonical timezone-aware window remains a green positive control.

Expected RED on #100: all six falsy invalid values skip their respective
truthiness guard and `is_current()` returns true.

No model/scope/activation source is modified; PR #100/#104 retains source
ownership.

Safety: temporal authorization narrowing only; no network I/O, target
interaction, scanning, execution, remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
