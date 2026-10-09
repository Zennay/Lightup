# Scope authorization: cumulative risk-budget reference (offline)

This additive, stdlib-only test reference models a **single** atomic reservation against an already authenticated grant. It does **not** issue approval, authenticate a grant, lock concurrent consumers or authorize any live target. The production source owner must review and implement it separately.

## Required production contract

- Bind the budget to **tenant, request and authorization revision**. Any mismatch denies.
- Treat `limit`, `used`, and requested `units` as exact non-boolean integers; reject malformed, negative, exhausted or oversized values.
- Reject inactive grants, unapproved attempts, noncanonical identities and polymorphic envelopes.
- Reserve atomically under a durable per-grant lock or compare-and-swap transaction; concurrent workers must **not** both spend the same remaining units.
- Persist attempt-id idempotency keys and reservation/commit/rollback events; do not refund an already executed attempt through a worker restart.
- Revalidate live revocation, grant provenance, time window, target, mode, capability and risk level at dispatch. A budget check by itself never authorizes an action.

Run the isolated tests with `python -m unittest tests/test_scope_risk_budget_reference.py`. No network, target scanning, real approvals or capability dispatch occur. Keep draft until exact-head Python 3.11/3.14 + permanent VPS CI and production-owner review.
