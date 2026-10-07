# Pre-authorization engagement lifecycle execution acceptance

Tracks #651 as a collision-free acceptance contract above the active durable execution resolver source owner PR #554.

## Pinned source owner

- Parent PR: #554
- Parent head: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`
- Branch: `chatgpt/scope-authorization-preauth-lifecycle-execution-red-20261007`
- Production source changes in this branch: **0**

## Threat

The durable execution resolver validates that the persisted engagement status is a known `EngagementStatus` and rejects `CLOSED`, but it currently accepts every other canonical status. That means a structurally current grant attached to a durable `DRAFT` or `AUTHORIZATION_PENDING` engagement can be reconstructed as live execution authority.

Execution-time defense in depth must not rely on the issuance path having been correct historically. Pre-authorization lifecycle state cannot mint target-active authority from an already-persisted grant.

## Required contract

- `DRAFT` is non-executable.
- `AUTHORIZATION_PENDING` is non-executable.
- `AUTHORIZED` remains executable for an otherwise canonical current grant.
- `RUNNING` remains executable for an otherwise canonical current grant.
- `CLOSED` remains non-executable.
- Denial does not rewrite engagement status or mutate grant provenance/revocation state.
- `REMEDIATION` and `RETEST` are intentionally outside this narrow contract.

## Expected state on the pinned parent

The `AUTHORIZED`, `RUNNING`, and `CLOSED` controls should remain green.

The two pre-authorization methods are intentionally **RED** until PR #554 absorbs the lifecycle allowlist: its current resolver rejects only `CLOSED` after enum reconstruction.

## Collision boundary

This branch adds only this document and its dedicated regression module. It does not modify `src/lightup/domain.py`, #177 request-to-grant provenance, #550/#551 lifecycle-integrity ownership, #100/#107/#112 activation/dispatch code, execution policy/orchestration, evidence-remediation, handlers, deployment, verdict or attack-path lanes.

## Safety

Temporary-SQLite authorization narrowing only. No DNS/network I/O, target interaction, scanning, exploit behavior, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
