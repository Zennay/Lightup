# Canonical grant-validity datetime contract

This acceptance slice pins the runtime datetime object boundary at durable
client-grant issuance above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Invariant

`DomainStore.record_authorization_grant()` must receive exact built-in,
timezone-aware `datetime` objects for both `valid_from` and `valid_until`.

The existing ordering check operates on the in-memory objects, while durable
state is written later through `isoformat()`. A datetime subclass can therefore
behave like a short, valid authorization window during comparison and override
serialization to write a different, still parseable window.

Two authority-widening examples are pinned:

- a one-hour `valid_until` object serializes an expiry roughly ten years later;
- a recent `valid_from` object serializes a start roughly ten years earlier.

Those strings remain valid timezone-aware ISO timestamps, so execution-time
malformed-timestamp validation cannot distinguish them from ordinary persisted
authority. The issuance boundary must reject polymorphic datetime objects before
any row is written.

## Acceptance proof

`tests/test_scope_authorization_grant_validity_datetime_types.py` provides:

- a canonical exact aware-datetime green control;
- a benign datetime-subclass rejection proving the exact runtime type boundary;
- a later-expiry serialization spoof;
- an earlier-start serialization spoof;
- row snapshots proving rejected inputs cannot create or mutate durable grants.

The two spoof cases additionally inspect any accidentally persisted row and fail
if polymorphic `isoformat()` output changed the durable authorization window.

Against exact #554 source, the subclass cases are intentionally expected RED
until the domain authorization owner adds the narrow exact-datetime guard.

## Separation from existing owners

- #347 pins `AuthorizationGrant.is_current()` time-window semantics.
- #470/#471/#554 cover malformed, timezone-naive, or otherwise corrupt
  timestamps when durable state is later resolved for execution.
- This contract is earlier: it prevents a polymorphic issuance input from
  creating a different but syntactically valid persisted time window.

## Collision boundary

Tests/documentation only. No changes to `src/lightup/domain.py`,
`src/lightup/engagements.py`, execution policy/orchestration, evidence
remediation, or target-capable source.

## Safety

Temporary SQLite and in-process grant construction only. No DNS/network I/O,
target interaction, scanning, exploit behavior, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
