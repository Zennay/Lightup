# Scope authorization: restore anti-rollback reference

Status: **offline, non-production reference only**. This change does not issue, approve,
restore, or activate any permission and never contacts a target.

## Threat boundary

A backup, reconstructed queue event or disaster-recovery snapshot may contain a
previously valid grant. Copying its `active=true` flag back into the current
authorization register could resurrect a revoked, superseded or narrowed grant.
Snapshots and their revision numbers are claims, not current issuer authority.

## Required production invariant (for owner review)

Restored state must remain **quarantined / inactive** until an issuer-controlled,
authenticated current-state lookup confirms tenant, grant identity, exact revision,
active status and scope/risk/capability bounds. Reject if the issuer is unavailable,
if revisions differ in either direction, if a tombstone or revocation exists, or
if identity/typing is ambiguous. A restored grant must not override newer durable
revocation/tombstone information. An ordinary equality match is **not** provenance:
an attacker could forge matching objects or roll back both sides of a database.

The production owner must use anti-rollback state held outside the restored snapshot
(e.g. authoritative monotonic issuer epochs or durable independently protected
revocation markers), revalidate expiry, consent, approver provenance, risk and exact
scope, and re-check immediately at dispatch and between steps. Recovery should
prefer non-executable, operator-reviewed reconciliation. Never infer authority
from backup signatures alone, copied timestamps, cached eligibility or these tests.

## Independent acceptance examples

- Restored stale grant against a newer revoked current record: **deny**.
- Same-revision inactive current grant against saved active record: **deny**.
- Reissued grant, cross-tenant or cross-grant restore: **deny**.
- Future/forged revision, bool-as-int, truthy approval, malformed envelope: **deny**.
- Exactly matching active typed values: *reference conditionally eligible only*,
  never proof of actual permission or a production authorization decision.
- Issuer unreachable or both sources restored together: **deny** in production,
  because independent trusted anti-rollback authority is missing.

Offline check:
`python -m unittest discover -s tests -p test_scope_restore_rollback_reference.py -v`

The main production executor remains owned by PR #107; no production files,
release gates or other workers' branches are changed. Require exact-head hosted
and permanent VPS proofs and source-owner review before any integration.
