# Scope authorization: type-safe engagement closure and atomic revocation

Issue: #653  
Source owner: draft PR #554 / existing revocation owner #100  
Exact parent head: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

`DomainStore.set_engagement_status()` persists the caller's `status.value`, then decides whether to revoke grants with object identity:

```python
if status is EngagementStatus.CLOSED:
    ...
```

The type annotation is not runtime enforcement. A duck-typed object whose `value` is the canonical text `closed` therefore writes a durable closed engagement but is not identical to `EngagementStatus.CLOSED`, so the atomic grant-revocation branch is skipped.

While the durable row remains closed, draft #554 still denies execution. The deeper lifecycle problem is that the old grant was never revoked. If the engagement is later moved back to an executable lifecycle state, that old grant can become live again without a fresh authorization event.

## Contract

Lifecycle mutation must accept only a canonical `EngagementStatus`.

A non-canonical closed-like object must fail before either:

- updating `engagements.status`; or
- mutating any `authorization_grants` revocation field.

Canonical `EngagementStatus.CLOSED` must continue to atomically populate `revoked_at`, `revoked_by`, and `revocation_reason` for every unrevoked grant.

After canonical closure, moving the engagement back to `AUTHORIZED` must not resurrect the revoked grant.

## Expected RED on #554

The regression supplies a simple object with:

```python
value = EngagementStatus.CLOSED.value
```

Current source persists that value successfully, skips the identity-based closure branch, and returns a normal `EngagementRecord` parsed from the now-canonical database text. The acceptance test instead requires rejection before mutation.

No malformed persisted enum is involved, so this is separate from #550/#551.

## Independence

- #100 owns normal revocation operations and closure revocation behavior.
- #550/#551/#554 own execution-time persisted lifecycle integrity.
- #560/#562 own persisted revocation metadata coherence.
- #651 owns pre-authorization lifecycle denial at execution.

#653 only proves the lifecycle-mutation input cannot bypass the revocation side effect.

## Collision and safety

This branch adds only:

- `tests/test_scope_authorization_closure_type_revocation.py`;
- `docs/scope-authorization-closure-type-revocation.md`.

There are **0 production/source changes**. Existing domain/revocation owners keep production ownership.

The proof uses temporary SQLite only. No DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation occurs.
