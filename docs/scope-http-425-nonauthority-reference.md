# HTTP 425 Too Early / Early-Data are never scope authority

This is a **pure stdlib offline synthetic reference**, not the production authorization engine. HTTP status 425 (Too Early), a later retry yielding 2xx, and request `Early-Data` metadata describe request transport/replay handling; none proves customer consent, approver identity, issuer authenticity or an active permission grant.

## Required production boundary
- Every attempted dispatch (including retries after 425) must independently revalidate current issuer-authenticated grant provenance, tenant, request, asset, capability, approval revision, expiration, revocation, risk budget, and global active-execution gate. Fail closed on missing, stale, invalid or ambiguous evidence.
- A proxy response, header, status, TLS early-data indication or successful retry must never mint, revive or broaden authorization. A previous successful dispatch never authorizes another dispatch.
- Preserve idempotency and replay controls separately from authorization. A safe retry must not circumvent attempt budgets or revocation checks.
- Audit denials without leaking tokens, credentials, or private target details; use minimal typed reason codes.

## Regression fixture
`python -m unittest discover -s tests -p 'test_scope_http_425_nonauthority_reference.py' -v`

Thirteen offline tests exercise revoked grants, cross-tenant/request/asset/capability boundaries, stale revision and strict types, control characters, polymorphic envelopes, hostile transport metadata, and immutability. Two explicit retry-sequence regressions demonstrate that a previously matching grant cannot bypass later revision changes or consent withdrawal. Positive synthetic consistency is only a *necessary* condition; it does not authenticate a real issuer or enable any capability.

## Merge gate
Draft until exact-current-head hosted Python 3.11/3.14 and canonical permanent VPS CI pass and production scope owner reviews integration. Never treat this reference as evidence of real-target authorization. No network, DNS, scanning, permission activation, production executor modifications or deployment.
