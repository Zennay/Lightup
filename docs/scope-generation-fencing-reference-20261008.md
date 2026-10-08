# Scope authorization: generation fencing reference (M7/ST5)

This isolated PLAN/LAB reference defines a **non-authoritative** revocation/reissue race boundary. An authorization snapshot from generation N must never regain eligibility after revocation and subsequent issuance of generation N+2. Identifiers bind the fence to exactly one tenant, engagement, and grant. Revocation advances a tombstone; subsequent issuance must exceed the tombstone. Stale issuers cannot lower the generation.

## Offline reproduction

```sh
python -m unittest discover -s tests -p 'test_scope_generation_fencing_reference_20261008.py' -v
```

Nine offline tests model unissued denial, current reference eligibility, revocation, reissue above tombstone, cross-tenant/engagement/grant isolation, strict generation typing, stale issuer rollback denial, and idempotent repeated revocation.

## Critical limitations and integration gates

- The pure in-memory ReferenceFence in the test is **not** a production authorization mechanism. A passing test does not authorize any target or capability.
- Production requires an authoritative, durable, transactional generation store; atomic compare-and-swap and dispatch-side revalidation immediately before every capability step. Local instance state and eventual-consistency replicas cannot grant permission.
- Credentials, explicit asset/capability/risk allowlists, tenant entitlement, independent human approval, expiry, trusted grant lineage, and audit availability remain independent mandatory gates. Generation equality **never** grants permission on its own.
- A lost or unavailable authoritative store must deny, not default to generation 1. A revoked generation must remain fenced across restarts and even when the same grant ID is reissued.
- Concurrent in-flight operations must be cancelled or denied at each step; single-point checks are insufficient.
- Runtime executor integration belongs to PR #107; revocation matrix/reference owners #983/#989 remain unchanged. This contribution touches only newly added isolated test and docs paths.
- No live targets, DNS, sockets, scanning, dispatch, production configuration or permission widening.
- Keep draft until source owner review, source-integrated concurrency tests, and successful exact-head hosted and permanent canonical VPS CI evidence. Do not interpret local/offline model success as production proof.
