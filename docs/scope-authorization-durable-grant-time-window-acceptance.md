# Durable grant time-window acceptance

Tracked by #347.

## Contract

`AuthorizationGrant.is_current()` is a deterministic in-memory temporal gate for durable authorization grants.

The acceptance suite proves that:

- `valid_from` and `valid_until` are inclusive;
- instants before the start and after the expiry are not current;
- timezone-aware representations of the same instant compare consistently;
- a timezone-naive explicit evaluation clock is rejected;
- an inverted directly constructed window can never become current.

## Collision boundary

This branch is tests/docs only. It does not modify `src/lightup/engagements.py`, `domain.py`, execution policy, activation, orchestration, webapp, durable persistence, or target-capable code.

The separate #734 child owns exact-type rejection for polymorphic caller-supplied evaluation datetimes. #647 owns issuance/persistence datetime integrity. Legacy `models.Authorization` time semantics are separate.

## Safety

Pure datetime behavior only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
