# Scope authorization: cumulative risk-budget reference (offline)

This additive, stdlib-only test reference models a **single sequential** reservation against an already authenticated grant. It does **not** issue approval, authenticate a grant, lock concurrent consumers or authorize any live target. The production source owner must review and implement it separately.

## Required production contract

- Bind the budget to **tenant, request and authorization revision**. Any mismatch denies.
- Treat `limit`, `used`, and requested `units` as exact non-boolean integers; reject malformed, negative, exhausted or oversized values.
- Reject inactive grants, unapproved attempts, noncanonical identities (ASCII alphanumeric initial character followed by at most 127 ASCII alphanumeric, period, underscore or hyphen characters), control characters, invisible Unicode aliases, polymorphic envelopes and implicit numeric coercion.
- Reserve atomically under a durable per-grant lock or compare-and-swap transaction; concurrent workers must **not** both spend the same remaining units.
- Persist attempt-id idempotency keys and reservation/commit/rollback events; do not refund an already executed attempt through a worker restart.
- Revalidate live revocation, grant provenance, time window, target, mode, capability and risk level at dispatch. A budget check by itself never authorizes an action.

Run the isolated tests with `python -m unittest tests/test_scope_risk_budget_reference.py`. No network, target scanning, real approvals or capability dispatch occur. Keep draft until exact-head Python 3.11/3.14 + permanent VPS CI and production-owner review.

## Explicit reference limitations

The pure `reserve` function is deterministic and immutable, but **not** an atomic storage operation. Two callers reading the same stale `used` value could both receive a successful result. Production must use a serializable transaction or compare-and-swap on the same authorization grant and revision, re-reading revocation inside that transaction; the supplied tests are not concurrency proof. Budget units must be defined by the issuing authority and may not be inferred from a UI label or a client-supplied cost. Reject stale reservations when the authorization revision changes. Do not retry a rejected operation automatically with fresh identifiers.
