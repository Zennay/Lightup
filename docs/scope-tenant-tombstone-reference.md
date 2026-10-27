# Tenant deletion tombstone: offline authorization reference

**Status:** proposed necessary condition only; no production authorization, issuer proof, or approval.

A deleted tenant must never retain active assessment authority just because a cached grant or a stale worker snapshot says `active=true`. Likewise a tenant identifier reused after deletion must not reactivate a grant from the prior tenant incarnation.

## Proposed contract for the production owner

- Keep an issuer-owned, monotonically increasing **tenant incarnation/generation** in the inclusive signed-64-bit range `1..2^63-1` (fail closed at exhaustion; never wrap or recycle) and durable deletion tombstone; never infer deletion from an absent or user-supplied UI field.
- Bind every issued grant to tenant identity **and incarnation**. On delete, revoke/cancel in-flight leases and deny later dispatch. Re-creation must receive a new incarnation.
- At **admission and immediately before every dispatch**, read trusted current tenant lifecycle, grant revision/revocation, independent approvals, capability, risk, target and execution-window state. Any lookup error, timeout, stale cache or mismatch denies.
- Make tombstone writes, grant invalidation and work-queue cancellation atomic or implement a fail-closed barrier that denies dispatch while they converge. Record audit receipts without tenant-sensitive payloads.
- Do not rely on a bool, generation integer or matching tenant label supplied by a requester. Both dataclasses in the test are **synthetic fixtures**, not authenticated records.

## Offline regression

`python -m unittest discover -s tests -p 'test_scope_tenant_tombstone_reference.py' -v`

Twenty stdlib-only cases test deletion denial, tenant reincarnation, older snapshots, tenant swaps, inactive/truthy flags, malformed identities and types, subclassed grant/state records, generation boundaries, grant identifier rejection, overflow and non-integer generations, signed-64-bit boundary and input immutability. Passing the positive reference case is **not permission to run a scanner**.

## Ownership / safety

This additive tests/docs-only branch does not edit the production executor owned by PR #107 or other scope workers. No DNS, sockets, network, real targets, scanning, capability dispatch, deployment or grant widening. Keep draft pending exact-head hosted Python 3.11/3.14 and canonical self-hosted VPS proof, production-owner integration and review.
