# Scope authorization: evaluation-instant type acceptance

Issue: #403

This tests/docs-only contract is stacked on exact active PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Boundary

A supplied `Authorization.is_current(now=...)` value is security-sensitive
clock input. Only `None` may mean "use the current wall clock". Any supplied
non-`datetime` value must fail closed rather than being interpreted through
Python truthiness.

The acceptance covers the falsy values `0`, `False`, and `""`, each of
which current code silently replaces via:

`now = now or datetime.now(timezone.utc)`

A canonical timezone-aware datetime remains a green positive control and
`None` retains the intentionally omitted-clock behavior.

## Distinct ownership

- #295 covers temporal boundary/inclusive semantics and timezone-aware datetime
  evaluation;
- #301 covers type confusion in stored `valid_from` / `valid_until`;
- #403 covers type confusion in the caller-supplied evaluation instant itself.

## Collision boundary

Only one regression module and this document are added. No #100/#104 source,
#295/#301 files, scope/activation/domain/state/execution-policy/webapp code, or
target-capable code is modified.

## Safety

Temporal authorization-input narrowing only. No network I/O, target
interaction, scanning, execution, remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
