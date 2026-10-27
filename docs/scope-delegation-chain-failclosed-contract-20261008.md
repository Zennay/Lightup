# Delegated scope authority: fail-closed acceptance contract (offline)

Status: **reference specification only**, M7/ST5 plan/lab. This document does not issue permissions, integrate a runtime authorizer, or authorize target contact. Production executor ownership remains with PR #107 and human approval/revocation owners.

## Confused-deputy boundary

A service account, worker or coordinator acting for a tenant may carry *less* authority than a human-approved grant, never more. An authenticated caller or job identifier is not sufficient proof of a grant. Every delegated hop MUST bind an immutable trusted parent-grant identifier, tenant ID, subject/audience, exact permitted capability set, asset/resource identity, consent revision, risk ceiling, validity interval and issuer lineage. Delegation to another actor is forbidden unless the trusted parent explicitly authorizes delegation. A child MUST be a strict subset or equal in permissions and expiry to its parent; a child cannot change tenant, resource or approval revision.

For a chain, enforcement MUST reconstruct and validate the entire chain from trusted issuance records on **every admission, retry and dispatch**, not merely accept claimant-supplied signatures or a cached Boolean. Reject a missing or inactive ancestor, unknown issuer, circular reference, repeated grant identifier, chain exceeding the configured bound, a child with an earlier start than the parent, expiry after any parent expiry, or an untrusted/mutable parent snapshot. A parent revoke, offboarding or approval revision change invalidates descendants immediately, including already queued jobs. On storage/clock/audit verification outage: deny, do not defer enforcement to an active step.

No delegated actor may substitute one tenant's service credentials or a shared coordinator identity to operate on another tenant's approved asset. The authorization decision is recomputed independently of diagnostic correlation IDs and request headers. The chain must be replay-safe: duplicate jobs and retries cannot upgrade effective permission.

## Negative acceptance matrix

| Scenario | Required decision |
| --- | --- |
| Child changes tenant, asset, audience or consent revision | Deny |
| Child adds a capability or increases risk ceiling | Deny |
| Child expiry extends past parent; child starts before parent | Deny |
| Parent revoked, expired, offboarded or superseded | Deny descendants, including queued/retry |
| Missing ancestor, broken issuer lineage, cycle, duplicate grant ID | Deny |
| Parent delegation disabled but child delegated | Deny |
| Chain exceeds configured maximum depth | Deny |
| Shared worker identity reused across tenants | Deny |
| Inconsistent records or unreadable trusted grant store | Deny |
| Authorized child only within all live ancestors' intersection | Conditionally eligible; not execution permission |

## Production handoff and evidence

The source owner must define canonical identifiers, trusted grant store/issuer provenance, bounded depth, clock source, monotonic revocation semantics, and an atomic pre-dispatch check. Demonstrate negative source-integrated tests (including a race between queue admission and dispatch), exact-head hosted CI and permanent VPS evidence, then obtain an explicit human review before promotion. Offline documentation or a mocked positive control is **not** evidence that production delegation is enforced.

No real target, DNS, socket, scan, executable capability, deployment, grant issuance or permission widening belongs to this contribution.
