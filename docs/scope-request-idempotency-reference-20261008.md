# Offline authorization request idempotency reference (2026-10-08)

Scope: test-only, synthetic, pure-memory model. Does **not** change the production executor, grant issuance, approval workflow, risk policy, permissions, target access, or activation state.

## Boundary
- A new (tenant, engagement, client nonce) request enters **pending review only**, never automatic approval.
- An exact retry of the same digest remains pending. A reused nonce with a changed canonical request digest is denied without overwriting the original.
- Tenant and engagement identities are in the key; cross-tenant/engagement requests cannot consume one another's nonce.
- Nonempty ASCII string identities/nonces and canonical lowercase 64-character SHA-256-style hex digest shapes are screened with exact Python types (bool is not int/string). This is a shape check, not cryptographic verification.
- A malformed existing record denies rather than silently resetting trust state.

## Production integration requirements (not satisfied by reference)
1. Authenticate principal and bind server-issued tenant and engagement context; never trust client-provided routing fields.
2. Compute digest on canonical server-side schema, including **all** approval-relevant fields, asset and capability scope, risk bounds, expiration and policy version.
3. Use durable, atomic uniqueness (compare-and-insert / transactional constraint), not a read-then-write race; preserve nonce history across worker restarts.
4. Enforce bounded retention that covers the entire replay threat window, with safe treatment of expired/tombstoned nonce entries.
5. Revalidate live approval, revocation, grant provenance, tenancy, risk, and exact current scope independently of request idempotency on every attempted execution.
6. Emit secret-minimized audit receipts for duplicate/mismatched requests; reject request conflicts without exposing the prior payload.
7. Prove concurrent submissions, retries after crash/restart, replay after expiry, and cross-region races in integration tests.
8. Obtain source-owner review and exact-head hosted + canonical permanent VPS CI evidence before integration or release.

## Reproduction
`python -m unittest discover -s tests -p 'test_scope_request_idempotency_reference_20261008.py' -v`

The test checks only this isolated reference predicate. It is **not** a production test, a CI-green assertion, permission to scan, or a basis for real-target activity. Existing runtime executor ownership stays with PR #107. Other workers' approval/revocation/evidence source files remain untouched.
