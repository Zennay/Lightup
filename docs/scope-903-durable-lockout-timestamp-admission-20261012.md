# #903 — durable authentication lockout timestamp admission

**LightUp Incubate M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.**

## Why this independent work
[Issue #903](https://github.com/Zennay/Lightup/issues/903) documents that `DomainStore.authenticate` reads `login_failures.locked_until` from SQLite and directly calls `datetime.fromisoformat`, then compares against an aware UTC timestamp. Malformed text raises incidental `ValueError`; timezone-naive time raises `TypeError` on comparison. Those are not the controlled `AccountLockedError` the authentication contract requires. This is an admission/accounting weakness; not a successful login-bypass demonstration.

Production source ownership stays with [PR #670](https://github.com/Zennay/Lightup/pull/670), and adjacent concurrent-login accounting #910 remains with its separate active worker. Baseline: unchanged `main` `05b80319cd0581fed21fe9d8f565bcb0a56cd2df` (2026-10-12). This branch adds **one isolated SQLite test file and this documentation only**, no `domain.py`, web session, CLI, policy, grants, report, Nginx, main, or concurrent source-owner changes.

## Actual disposable SQLite acceptance
`tests/test_scope_903_sqlite_lockout_timestamp_20261012.py` tests against a new temporary `DomainStore` database and synthetic login account. Its 10 unittest methods cover:

- Two green aware-future lockouts (UTC and non-UTC offset) with exact `AccountLockedError`, and future locked-row immutability over repeated attempts.
- Green aware-expired state preserving authentication and clearing the failure row; ordinary wrong-password counter.
- **Three deliberate expected RED** canaries: malformed ISO text, timezone-naive future state, and controlled denial before password verification or persistence.
- Green characterization of present malformed-row immutability; do not confuse accidental parser exception with controlled fail-closed auth.

Everything runs within disposable SQLite and Python unit mocks; no deployed database, client credentials, network, targets, scans or executions.

## Required source-owner repair and proof
Before password verification, validate `locked_until` is canonical structured text with an aware UTC-comparable offset and bound; reject malformed/out-of-range/naive durable timestamps as a **single deterministic controlled `AccountLockedError`**, without leaking source input. Keep original row unchanged on malformed state; no auto-heal that could reset lockout. Preserve canonical future lock and expired behavior, and account for #910's concurrent SQLite failure-counter semantics. Independent reviewer should inspect lifetime/transaction boundaries and confirm no new login bypass window.

Convert all three XFAILs into normal passing negative tests **only after** source owner integrates enforcement; then run actual authenticated WSGI and negative-state tests, exact SHA GitHub-hosted Python 3.11/3.14 plus *separate permanent registered VPS LightUp CI*, latest-main safety composition, security/privacy review, explicit owner authorization. This reference alone must not be merged, deployed, or marked as closed.

```bash
PYTHONPATH=src python -m unittest -v tests.test_scope_903_sqlite_lockout_timestamp_20261012
```
