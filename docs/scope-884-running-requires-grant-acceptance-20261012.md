# Scope #884 — persisted RUNNING lifecycle requires a current grant

**Project: LightUp Incubate M3/M7 PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.**

## Production gap and collision guard
Open [issue #884](https://github.com/Zennay/Lightup/issues/884) describes `DomainStore.set_engagement_status(..., RUNNING)` permitting a direct transition from DRAFT or AUTHORIZATION_PENDING when there is **no current engagement-bound authorization grant**. The current source owner is [PR #107](https://github.com/Zennay/Lightup/pull/107). This branch is pinned on exact unchanged main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df` and adds only a separate new test and this documentation. It does not modify production `domain.py`, current grant selector, original owner branch, target engine, evidence, ingress, activation, queue or any parallel PR.

## Implemented offline synthetic proof
`tests/test_scope_884_running_current_grant_20261012.py` provides **12 real, disposable SQLite** `DomainStore` unittest methods:

- Six intentional expected RED canaries prove DRAFT, AUTHORIZATION_PENDING, expired-grant, not-yet-valid-grant, other-engagement grant and CLOSED/reopened lifecycle cases can become RUNNING without the required current authorization checks in the default producer. Each negative assertion includes a required unchanged durable status after future source-owner repair.
- Green positive source controls: `AUTHORIZED -> RUNNING` with a current same-engagement persisted grant, persisted valid-grant roundtrip, no-grant new DRAFT, client role denial, cross-tenant read isolation, current-grant selector expiry/future denial.
- Source read and SQLite state only. There is no active target, network, real asset, tool execution, scope expansion, scan, remediation or deployment.

## Production owner handoff
A source-owner fix must guard the **DRAFT/AUTHORIZATION_PENDING/CLOSED -> RUNNING** transitions using a live, persisted, same-client/same-engagement, unrevoked authorization grant, with correct validity bounds. It must revalidate at the exact durable status transition to eliminate time-of-check/time-of-use gaps and preserve previous durable status when denied. No UI-provided scope or status is a grant. This is a lifecycle check, not a substitute for #107 pre-dispatch live grant revalidation, issuer/operator verification, tenant isolation or pre-I/O revocation.

These expected RED tests **do not** prove the system is safe, and no standalone test code fixes it. Convert all six to ordinary passing negative tests only after #107 owner integrates production source. Require real domain + WSGI + executor binding tests, exact-head Python 3.11/3.14 hosted and **separate registered permanent VPS CI**, security/privacy/tenant review, latest-main compatibility, explicit human release authority. Keep #884 OPEN, DRAFT/HOLD.

Reproduction on approved isolated checkout:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_884_running_current_grant_20261012.py' -v
```
