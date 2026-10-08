# M7/ST5 — mixed-tenant batch authorization atomicity (offline reference)

## Contract
A work batch must not convert a successful check on some elements into permission to execute those elements when any sibling is unauthorized. Batch admission is **deny-all** unless every member passes independently. This is an acceptance contract, not proof that the current production executor enforces it.

## Invariant and test mapping
1. Homogeneous, inert reference-only candidates may be marked eligible by a local pure function; this does **not** issue a grant.
2. Cross-tenant member -> reject the *whole* batch; no authorized subset is emitted.
3. Stale grant revision -> reject whole batch, including previously accepted siblings.
4. Any inactive, denied, missing or non-boolean approval -> reject whole batch.
5. Numeric booleans must never satisfy revision integers.
6. Duplicate work identifiers -> reject, preventing ambiguous retry/dedup accounting.
7. Missing, unexpected, malformed and empty members -> reject.
8. Inputs remain unchanged; validation cannot silently remove offending entries.

Offline regression module: `tests/test_scope_batch_tenant_atomicity_reference_20261008.py`.
Run: `python -m unittest discover -s tests -p 'test_scope_batch_tenant_atomicity_reference_20261008.py' -v`.

## Required production integration — owner #107
- Bind every member to immutable, issuer-owned tenant, engagement, asset, authorization revision and permitted capability, not to request-supplied labels.
- Atomically check entire batch against durable live approval/revocation state at admission and again immediately before each dispatch/retry/continuation.
- If a sibling is invalidated while work is queued or running, stop all not-yet-started work; abort or safely contain in-flight steps where possible. Never silently dispatch a remaining subset.
- Do not authorize a batch based on local dataclass equality, this reference predicate, a correlation identifier or untrusted client payload.
- Deny on inconsistent snapshots, lease races, audit-storage failure, unavailable authority store, epoch mismatch or inability to cancel safely.
- Emit redacted, immutable denial evidence; do not leak target secrets or promote a batch based on log success alone.

## Release gate
Keep draft / PLAN-LAB ONLY. No active targets, DNS, HTTP, scanners, capabilities, consent grants or deployments. Require review from authorization source owner #107, source-integrated negative tests, exact-head hosted CI and canonical permanent VPS proof, and an explicit human release decision before calling this production-safe.
