# Durable grant evaluation datetime exact-type acceptance

Tracked by #734.

## Boundary

`AuthorizationGrant.is_current(now=...)` is an authorization-time decision boundary. A supplied evaluation instant must be either omitted or an exact built-in timezone-aware `datetime`.

This contract is narrower than:

- #347, which owns the general durable grant time-window semantics;
- #647, which owns exact validity datetime integrity during durable grant issuance/persistence;
- #733, which applies the same exact evaluation-time principle to the separate legacy `models.Authorization` object.

## Required behavior

The acceptance suite requires:

1. exact built-in aware datetimes to preserve inclusive `valid_from` / `valid_until` boundaries;
2. a `datetime` subclass to be rejected before it can participate in the lower-bound comparison;
3. a `datetime` subclass to be rejected before it can participate in the upper-bound comparison.

The adversarial subclass deliberately overrides rich comparisons so a future or expired grant can otherwise appear current. Rejection must be controlled and fail closed.

## Expected state on current source

Current `AuthorizationGrant.is_current()` checks timezone awareness but not exact type, so the two subclass cases are expected RED until the production owner adds an exact-type guard. The canonical inclusive-boundary control is expected GREEN.

## Collision and safety stop line

This branch changes tests and documentation only. It does not modify `src/lightup/engagements.py`, durable issuance/persistence, domain resolution, execution policy, orchestration, activation, target-capable workers, evidence-remediation, deployment, verdicts or attack-path state.

The proof is deterministic and in-memory only: no DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authority widening.
