# Scope-authorization #910 — independent SQLite login-failure race acceptance (2026-10-12)

**Posture:** LightUp INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD/NO MERGE/NO DEPLOY.

## Owner-safe, additive slice

The existing domain/auth source owner is draft [PR #670](https://github.com/Zennay/Lightup/pull/670), pinned at `68318a318d828815bc50002114f64037ed06387e`. This branch contains only the new `tests/test_scope_910_login_failure_atomicity_independent_20261012.py` and this document. Neither `src/lightup/domain.py` nor any other worker branch, existing regression, permanent runner configuration, or production authentication path changes.

[Issue #910](https://github.com/Zennay/Lightup/issues/910) identifies a read/modify/write race: a login-failure row is read before password verification, while the increment is later computed using that stale row in another transaction. Two identical failed logins can consequently persist only one failure. The source owner must repair the **entire** read/check/verify/failure-accounting lifetime, and review concurrent valid login, lockout expiry, and mixed success/failure interleavings separately.

## New genuine disposable SQLite tests

- Canonicalize whitespace/case in a failed email; persist one failure without any user/session creation.
- Four ordinary sequential failures increment 1–4; the fifth creates the normal lockout, and a locked attempt does not call password verification.
- Canonical variants of the same email coalesce to one lockout counter; simultaneous counters for distinct fake emails do not mingle. Counters for two different fake `.invalid` addresses remain separate.
- Interleave two real `DomainStore.authenticate` calls at the password-verification boundary (the password verifier is **stubbed**, so no real secrets or expensive hashes are used). Demand both complete, both fail, and zero session rows.
- **Four explicitly `@expectedFailure` RED contracts**: fresh counter `0→2`, existing counter `1→3`, mixed-case/canonical-email aliases concurrently counting `0→2`, and threshold crossing `3→locked` after two simultaneous failures (instead of remaining unlocked with count 4). On the current source these lose an increment and must **not** be misreported as passing production hardening.

The bounded 650 ms verifier rendezvous deliberately allows a prospective `BEGIN IMMEDIATE` implementation to serialize the second read without test deadlock. Expected RED is **not** a security pass: a future successful repair must remove all four `@expectedFailure` decorators and rerun the exact-head suite. Unrelated failures or timeouts must not be treated as validated behavior by reviewers.

## Reproduction / release contract

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_910_login_failure_atomicity_independent_20261012.py' -v
```

The source owner should add a single transactionally serialized counter read/check/update with a bounded busy timeout, avoid stale overwrites, verify same-email vs distinct-email contention, and preserve user/session and lockout semantics. Its repair may require moving password verification under a per-email transactional fence or using a correctly bounded atomic SQL increment plus lockout decision; neither strategy is automatically accepted by these tests alone.

After source-owner integration: independently inspect full Python 3.11/3.14 diagnostics; verify exact branch HEAD + all test method names in raw job logs; obtain **separately registered permanent self-hosted VPS** run evidence; independently review SQLite lock contention, audit/data minimization and authentication side effects. Existing issue stays OPEN until the source owner and authorized human reviewer explicitly accept the integrated fix.

**Nonclaims:** no real login was attempted, no real account/password/client data were used, no sockets/DNS/HTTP, no target interaction, no authorization grants, no scans or deployment. These are test oracles only, not an installed authentication guarantee.

## W4 email normalization and transactional purity

The current branch adds two **positive** real `DomainStore.authenticate` acceptance controls for a verifier exception (existing persisted counter unchanged, zero sessions) and a locked-out email with different ASCII casing/whitespace (no repeated verifier call). A fourth deliberately expected-RED canary checks two concurrent alternate spellings of **the same canonical email**, ensuring normalization cannot sidestep serializable failure counting. The revised bounded two-thread fixture accepts caller-supplied labels only for known synthetic `.invalid` variants and always checks the normalized key. These tests use no users/password hashes or network.
