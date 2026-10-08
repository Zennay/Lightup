# Authorization decision cache expiry: offline reference contract

Status: **proposed, tests-only reference**. This does not alter LightUp production admission, grants, session caches, or the execution path. The live source owner is PR #107.

## Fail-closed boundary

A cached positive decision is never a durable execution permit. A consumer must reject a result if its tenant or grant revision differs, the live grant is inactive/revoked, the clock is before evaluation, or the clock is **at or after** expiry. The expiry boundary is exclusive. A missing, untrusted, invalid, or type-confused field denies rather than coercing to an allow. A cached denial cannot turn into an allow.

An offline cache check is only a necessary condition: production must still re-resolve trusted issuer lineage, canonical scope/capability, consent, risk, revocation and policy at admission **and** dispatch. No clock rollback may revive a previously expired grant; the reference deliberately does not claim to solve monotonic clock or distributed invalidation semantics.

## Acceptance handoff

- Tests: `python -m unittest discover -s tests -p 'test_scope_cache_expiry_reference.py' -v`
- Nine deterministic stdlib-only cases, without DNS, network, target probing or capability execution.
- Production owner must choose cache invalidation, trusted clock, cancellation and race policy. An exact-head hosted + permanent VPS result and owner review are required before claiming integration.
- This separate two-file contribution does **not** claim authorization approval, production proof, passing CI, or deployment.
