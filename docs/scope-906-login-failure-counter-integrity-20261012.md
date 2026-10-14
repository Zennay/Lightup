# Scope authorization #906 — durable login failure counter integrity

**DRAFT / HOLD / NO MERGE / NO DEPLOY — Incubate M3/M7 PLAN/LAB ONLY.**

## Issue and independent ownership
[Open issue #906](https://github.com/Zennay/Lightup/issues/906) records that `DomainStore.authenticate()` currently trusts a raw SQLite `login_failures.failures` value; a correct password can clear an impossible counter without validating that it is a canonical integer in producer range. A wrong password can add to negative or non-integer stored values. The canonical production source owner remains [PR #670](https://github.com/Zennay/Lightup/pull/670). Adjacent #903 timestamp integrity and #910 concurrent failure-accounting branches must remain separately owned.

Pinned unchanged main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df` (2026-10-12). This isolated branch adds one test and one document only — no production `domain.py`, web, session/CSRF, state, grants, executor, network/targets, main or another worker's files changed.

## In-process real SQLite regression
`tests/test_scope_906_login_failures_sqlite_20261012.py` creates disposable SQLite databases plus synthetic operator credentials and exercises the real current `DomainStore.authenticate` code. Ten unittest methods:

- **Five deliberately expected RED** to show missing controlled `AccountLockedError` admission of a negative counter, an unlocked at-threshold counter, REAL and TEXT SQLite storage values, and missing pre-password denial. An XFAIL is an **unfixed gap** rather than passing security production acceptance.
- Green canonical state: zero-to-one increment, threshold transition into `failures=0` and an aware lockout timestamp, successful login clearing only a valid unlocked row, aware future lock refusing before password verification, and current bad-TEXT row immutability when incidental TypeError arises.
- Exact `typeof(failures)` is read back from SQLite: numeric-looking floats and TEXT must never be normalized into grant authority.

## Production source-owner acceptance
The source owner should atomically read and validate failure-state structure **before** password hashing/verifier. For an unlocked row require SQLite exact integer storage and `0 <= failures < LOGIN_MAX_FAILURES`. For a locked row require exact `failures == 0`, canonical aware `locked_until`, and consistent temporal bounds (#903). Deny impossible durable states with controlled non-leaking `AccountLockedError` and **no mutation** or login-failure reset. Preserve ordinary failure counting, lockout, successful-login behavior, and coordinate concurrency semantics with #910; a test-only SQLite transaction is not proof of a production concurrency fix.

```bash
PYTHONPATH=src python -m unittest -v tests.test_scope_906_login_failures_sqlite_20261012
```

Only after #670 source-owner integration converts all RED canaries to genuine passing negative assertions should the scope owner run real WSGI authentication, security/privacy/tenant review, latest-main composition, exact-HEAD Python 3.11/3.14 hosted suites and **separate registered permanent self-hosted VPS CI**, plus explicit human release approval. Keep #906 OPEN. No real clients, credentials, scan/target actions, grants, deployment or retest.
