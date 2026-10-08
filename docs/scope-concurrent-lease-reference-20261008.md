# Concurrent scope-lease reference boundary (offline only)

M7/ST5 isolated acceptance reference. **This does not mint a grant or authorize an assessment**. No network calls, target probes, executor wiring, or production policy changes.

## Proposed key and deny-by-default semantics

- A single active lease per exact canonical `(tenant, asset, capability)` at a time; overlapping runs and same-run replay both deny.
- Different tenant, asset or capability is independently eligible, subject to an **external** valid issuer-owned authorization grant and scope policy.
- Expiry uses a half-open interval: `expires_at > trusted_now`; expired/inactive records do not block later admissions.
- Missing/malformed lease, time, revision, identifiers or state deny without changing the prior state.
- Leases MUST NOT substitute for explicit human approval, current unrevoked authorization, risk ceilings, asset allowlists, test windows or live per-step checks.

## Production owner handoff (not implemented here)

Reference `admit` is a pure model and cannot prevent concurrent writers racing. Production must use a **durable atomic reservation** with uniqueness/transactional compare-and-swap across workers and crash recovery; reject stale revisions and clock rollback, validate trusted issuer lineage, normalize assets before lock-key calculation, and audit attempts without leaking cross-tenant data. Revocation must fence already queued/in-flight work and fail closed on state-store errors. All operations must revalidate the live grant before dispatch. Canonical ownership remains with executor PR #107; this branch adds only standalone tests/docs and must be reviewed by that owner.

Promotion requires exact-head hosted CI, permanent VPS tests, source-owner integration/review and explicit activation approval. Passing this model's unit tests is **not** evidence of production concurrency safety.
