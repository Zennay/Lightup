# Scope authorization: atomic batch admission (offline reference)

**Status:** Proposed fail-closed contract and pure in-memory reference tests only. This is **not** production authorization, a passing CI claim, or permission to execute capabilities.

When a future client API requests multiple authorization additions together, the entire set must be validated *before* any grant is issued, written, queued, or made visible. One denied, cross-tenant, duplicate, noncanonical, or already-issued entry rejects **the whole batch**, including earlier valid entries. No partial success, silent skip, or automatic retry with a reduced subset is permitted.

## Boundary conditions

- Explicit tenant identity is mandatory and exact; no cross-tenant mixing.
- Approval is an exact boolean, not a truthy value; grant objects and outer collections must use canonical types.
- Duplicate entries and collisions with existing grant identities deny the whole operation.
- Validation must be against one consistent authorization/revision snapshot. At commit, revalidate live approval, expiry, revocation, scope, capability, risk, tenant and revision atomically. A stale snapshot must fail closed.
- A real implementation must use a transaction with rollback and idempotency scoped to tenant, request revision and approval provenance; concurrent requests must not create partial grants. The reference model does **not** implement transactions or concurrency.
- Auditing of rejection must not leak credentials, tokens or other tenants' details.

## Acceptance handoff

`tests/test_scope_batch_atomicity_reference.py` contains offline stdlib examples for late denial, foreign tenant, duplicate and existing identities, truthy approval, polymorphic input, collection limits and immutability. These tests validate only the reference model, **not any LightUp production service**.

Production executor and issuance owners retain implementation responsibility. Existing PR #107 (ToolExecutor), approval-provenance #992, expiry/cache #1051, release-ledger #982 and revocation #983/#989 are untouched. No DNS/network I/O, scanning, handlers, active capability dispatch, or target interaction.
