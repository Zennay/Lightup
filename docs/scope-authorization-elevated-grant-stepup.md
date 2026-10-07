# Scope authorization — elevated grant step-up approval

Issue #881 pins the product risk-model invariant that client authorization at
`RiskLevel.ELEVATED` requires a completed step-up risk approval.

## Contract

At durable grant issuance:

- `STANDARD` and lower grant risk remain outside this additional step-up gate;
- `ELEVATED` requires a durable approved risk-elevation record;
- the approval belongs to the same engagement as the grant;
- its requested risk covers the grant maximum;
- missing, pending, denied and cross-engagement approvals do not authorize the
  grant;
- rejection happens before an `authorization_grants` row is created.

A canonically approved same-engagement elevation remains a positive control.

## Relationship to adjacent authorization work

This contract complements rather than replaces:

- #177, which binds a grant to an approved assessment request and its requested
  asset/mode/risk envelope;
- #133/#146 and their children, which own how risk-elevation decisions are
  validated and committed;
- durable execution-time grant revalidation, which remains downstream.

The grant-issuance boundary must require all applicable provenance gates, not
treat one as a substitute for another.

## Expected state on the pinned parent

Standalone #881 was first pinned to `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`. This composed copy is carried
unchanged above exact PR #107 head
`c37ee27d922a7dd400eee1db39268f4a6269e431`.

The standard-risk control and the canonically approved elevated control are
expected GREEN. Missing, pending, denied, cross-engagement and approved-but-
underpowered step-up cases are intentionally expected RED because the grant
issuer does not yet consult `risk_approvals`.

## Safety and collision boundary

Tests and documentation only. No production source is modified and no active
risk-decision or grant source branch is taken over. Future source repair belongs
to the grant-issuance composition owner once the shared domain surface is free.

The regression uses temporary SQLite only and performs no DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
