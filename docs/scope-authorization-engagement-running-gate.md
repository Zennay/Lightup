# Scope authorization — RUNNING lifecycle requires current grant

Issue #884 pins a narrow lifecycle/authorization invariant above exact live-grant
source owner #107.

## Contract

Entering `EngagementStatus.RUNNING` requires a current, unrevoked durable
authorization grant for that same engagement.

Acceptance cases:

- `DRAFT -> RUNNING` without a current grant fails closed and leaves DRAFT;
- `AUTHORIZATION_PENDING -> RUNNING` without a current grant fails closed and
  leaves AUTHORIZATION_PENDING;
- a canonically authorized engagement with a current grant may enter RUNNING;
- after CLOSED revokes historical grants, reopening to DRAFT does not let the
  revoked historical grant power a direct jump back to RUNNING.

This contract intentionally does not define the entire engagement transition
matrix. It only prevents durable target-active lifecycle state from existing
without current authorization.

## Relationship to adjacent work

- PR #107 retains source ownership for serialized closure, grant revocation and
  live execution-time re-resolution.
- #651 remains execution-time defense in depth for pre-authorization lifecycle
  states.
- #177 remains issuance-time assessment-request -> grant provenance.

The lifecycle guard is additive: durable state should be coherent even though
execution also revalidates authorization immediately before dispatch.

## Expected state on the pinned parent

Pinned parent: exact PR #107 head
`c37ee27d922a7dd400eee1db39268f4a6269e431`.

The authorized/current-grant positive control and close/revoke behavior are
expected GREEN. The no-grant RUNNING transitions and reopened-with-only-revoked-
grant transition are intentionally expected RED because the current status
setter accepts any canonical status value except for its closure side effects.

## Safety and collision boundary

Tests and documentation only. No #107 production source is modified. The
regression uses temporary SQLite only and performs no DNS/network I/O, target
interaction, scanning, capability execution, remediation/retest execution,
deployment, verdict creation or attack-path mutation.
