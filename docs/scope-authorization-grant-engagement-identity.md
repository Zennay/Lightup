# Scope authorization: canonical grant engagement identity

Issue: #652  
Source owner: draft PR #554  
Exact parent head: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

`DomainStore.record_authorization_grant(..., engagement_id: str, ...)` currently trusts the Python annotation and sends the caller-owned value to SQLite more than once.

The first bind resolves the engagement row and supplies its durable `client_id`. A later bind persists `grant.engagement_id`. Python's SQLite protocol accepts adaptable objects, so one non-string object can expose different TEXT identities on those two binds.

That makes lookup and persistence disagree: the lookup can select engagement A/client A while the inserted grant references engagement B/client B. The resulting row carries client A plus engagement B. Draft #554 correctly rejects that ownership drift during execution resolution, but the invalid authorization/audit record has already been minted.

## Contract

Durable grant issuance must require `engagement_id` to be:

- an exact built-in `str`;
- non-blank;
- the same canonical value used for engagement lookup and persistence.

Arbitrary SQLite-adaptable objects are not engagement identities, even when every adaptation returns the same existing ID.

A rejected non-canonical identity must fail before any SQLite adaptation and create no grant row. Canonical exact-string engagement IDs continue to work unchanged.

## Expected RED on #554

The exact source-owner head performs:

```python
row = con.execute(
    "SELECT client_id,status FROM engagements WHERE engagement_id=?",
    (engagement_id,),
).fetchone()
```

and later persists the caller-derived `grant.engagement_id` in the authorization-grant insert.

The regression uses a deterministic object implementing `__conform__(sqlite3.PrepareProtocol)`. On the current head its first adaptation returns engagement A and its second returns engagement B, so the call succeeds and persists cross-tenant-incoherent lineage. The expected contract instead rejects the object before either bind.

## Independence

This is issuance-time identity integrity.

- #552/#554 own execution-time durable grant/engagement ownership revalidation.
- #567 owns polymorphic runtime `ExecutionRequest.client_id` / `engagement_id`.
- #177 owns approved assessment-request → grant provenance.

None of those boundaries makes a non-canonical `record_authorization_grant` input safe to persist.

## Collision and safety

This branch adds only:

- `tests/test_scope_authorization_grant_engagement_identity.py`;
- `docs/scope-authorization-grant-engagement-identity.md`.

There are **0 production/source changes**. Draft #554 retains `src/lightup/domain.py` ownership.

The proof uses temporary SQLite only. It performs no DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
