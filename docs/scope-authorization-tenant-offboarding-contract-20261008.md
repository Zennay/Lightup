# Scope authorization — tenant offboarding fail-closed contract (M7/ST5)

Status: **proposed acceptance criteria, not production enforcement**. No target activation is authorized by this document.

## Invariant

Tenant offboarding is an irrevocable deny boundary for all existing approvals, queued jobs, retries, leases and issued capability handles belonging to the offboarded tenant. Removing a tenant row is not sufficient: authorization decisions must consult an issuer-owned, durable tenant lifecycle generation/tombstone at admission **and immediately before every dispatch or step**. Fail closed if this evidence is missing, inconsistent or unreadable.

## Acceptance matrix

| Scenario | Expected decision |
| --- | --- |
| Tenant is marked offboarding before new request | DENY before creating approval or queue item |
| Queued approved job followed by offboarding | DENY at dequeue; no handler invoked |
| Offboarding between two steps | Cancel remaining steps; DENY next dispatch |
| Retry of a previously approved operation after offboarding | DENY; old approval cannot resurrect the tenant |
| Old lease/capability handle presented after offboarding | DENY even if token signature or expiry still valid |
| Tenant ID re-created with the same external label | DENY old artifacts using immutable tenant incarnation/generation |
| Offboarding committed but audit delivery fails | DENY; durable stop cannot be rolled back by audit outage |
| Tenant lifecycle store unavailable or times out | DENY; no cached allow fallback |
| Offboard tenant A while tenant B remains active | A denied, B unaffected unless shared safety state is uncertain |
| Duplicate offboarding request | Idempotent deny; no new allow transition |
| Parallel dispatch races with offboarding commit | Define linearization point; no new dispatch may begin after committed tombstone |
| Offboarding followed by administrative reactivation | Require a **new** tenant incarnation and new human-approved grants; old tokens never regain authority |

## Required integration evidence

1. Identify authoritative tenant lifecycle store and atomic monotonic generation/tombstone semantics. Bind approval records, work items and dispatch snapshots to immutable internal tenant identity and incarnation.
2. Test admission, dequeue, every dispatched step, retry and cancellation interleavings against the authoritative state—not a stale cache. Explicitly prove no handler call on denied paths.
3. Verify the audit trail records revocation/offboarding decision reason, correlation IDs and lifecycle generation without credential contents or target-sensitive raw payloads. Audit failure must not restore allow.
4. Exercise negative cases for missing or type-confused tenant IDs, deleted/re-created IDs, storage failure, race conditions and cross-tenant isolation.
5. Collect exact-commit hosted checks and permanent self-hosted VPS checks, independent source-owner review and human release decision before enabling any target-active path.

## Ownership / limitations

This contract is deliberately documentation-only. Existing production executor authorization owner PR #107 remains solely responsible for integration. Existing revocation/generation, approval, receipt, rollback and audit workers retain their own files and implementation boundaries. This proposal adds no database migration, queue mutation, endpoint, network request, scan, target contact or runtime bypass. It does not claim that tenant deletion, cancellation or issued-handle invalidation is implemented.
