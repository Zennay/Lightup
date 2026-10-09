# Consent withdrawal: offline deny-only reference

This document and `tests/test_scope_consent_withdrawal_reference.py` describe an **isolated reference**, not production enforcement or an approval mechanism. No target I/O or execution is permitted by passing this reference.

## Invariants

1. A verified withdrawal for an exact grant identity makes that grant unusable for all subsequent decisions, including already-enqueued work.
2. Withdrawal does not create a replacement grant; renewed consent requires a separately issued and approved new grant with distinct identity, scope and evidence.
3. Replayed, stale, malformed or cross-grant withdrawal events fail closed without changing the original object. Malformed persisted state (including boolean revisions, nonboolean withdrawn flags, negative revisions and nonstring grant identifiers) is not authoritative, even if another layer reports a positive approval. A real event intake must verify origin, integrity, tenant and monotonically increasing revision before persistence.
4. Stale or replayed withdrawal events after a newer event must not mutate the persisted snapshot; a withdrawal for one grant must never alter another grant. A newer event cannot reverse a withdrawn state. Removal from a UI or an asynchronous cache is not restoration of consent.
5. At each execution boundary, the production owner must atomically reconcile revocation/withdrawal with current persisted grant state and reject an unknown or unavailable authoritative state.
6. A queued or running operation must stop before subsequent capability dispatch on withdrawal; cancellation acknowledgements must not be interpreted as authorization.
7. Issuer verification, tenant binding, scope, risk, allowed capability, expiry and explicit real-target activation remain independent mandatory checks.

## Integration ownership

Production `ExecutionPolicy`, `ToolExecutor`, storage and event intake belong to their existing owners (not this tests/docs worker). Require exact-head hosted and canonical VPS test evidence, concurrency/restart regression, owner review, and explicit real-target activation gate before any production promotion.

The offline reference intentionally models only lexical identity, revision ordering, and denial monotonicity; it does **not** establish trusted provenance or durable concurrent revocation semantics.
