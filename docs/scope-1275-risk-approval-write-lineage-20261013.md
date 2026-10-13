# #1275 — operator risk-approval decision lineage, offline source-owner RED contract

**Phase:** LightUp Incubate M3/M7; **PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY**.

## Finding and boundary

`DomainStore.list_risk_approvals` tenant **READ** coherence is tracked separately in #808/#809. This issue tests the **WRITE-side** `DomainStore.decide_risk_elevation()`: the currently installed method selects a pending approval by approval ID, checks operator role and requester self-approval, then updates its decision fields. It does not independently compare the approval's duplicated `client_id` with `engagements.client_id` for the referenced engagement. Corrupted/migrated/legacy rows can therefore be decided without a coherent tenant lineage.

These tests are **offline synthetic persistence characterization**. They do not establish an actual cross-tenant exploit, issuance of a grant, active security authorization, or any real incident.

## Independent real SQLite + WSGI acceptance

New `tests/test_scope_1275_risk_approval_decision_lineage_20261013.py` uses real unchanged `DomainStore`, disposable SQLite and a SQLite `AFTER UPDATE OF status` audit trigger. Valid operator decisions generate exactly one persisted status transition and audit row, while client/self-approval and duplicate decisions leave both unchanged. Six deliberately unresolved expected RED cases require atomic refusal (including zero audit records) when a pending approval has:

- the approval's duplicated tenant ID changed A→B without moving the engagement, for **approve and deny**;
- the approval's engagement pointer changed to an engagement owned by B while its duplicated tenant remains A, for **approve and deny**;
- an orphaned engagement (created only by an offline fixture connection with foreign-key enforcement explicitly disabled), for **approve and deny**.

An isolated real `LightUpWebApp` WSGI sub-suite exercises current authenticated operator session, real CSRF, client-session denial, anonymous redirect and **two deliberately expected RED** cases demanding fail-closed HTTP 400/403/409 for the same corrupt approval during operator approve or deny. All denial tests snapshot actual stored rows and the trigger audit ledger before and after; no write side effects permitted.

The WSGI acceptance class subclasses the SQLite fixture so its inherited integrity cases are exercised twice (standalone and through the WSGI fixture). This is intentional redundant real-path characterization, not an increase in unique invariants. `expectedFailure` is never success of the missing control.

## Ownership and safe workflow

No edits to `src/lightup/domain.py`, `decide_risk_elevation`, `src/lightup/webapp/app.py`, `main`, earlier #808/#809 testing/owner branches, active risk-approval decision source owner #146, or any other worker's file. No actual targets, network, client data, grants, scans, external LLM, remediation or retest.

Run from repository root (Python 3.11 and 3.14):
```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1275_risk_approval_decision_lineage_20261013.py' -v
```

Original source owner must implement a coherent engagement/tenant validation from an atomic *transactional snapshot* before any SQL UPDATE; compare affected row count, refuse partial/duplicate decisions and verify zero denied audit side effects. Web-layer integration should translate this to a safe 4xx with no private data in response. All expected RED tests must become **ordinary PASS without test relaxation** and existing safety canaries must remain passing. Exact-head hosted Python 3.11/3.14, separately registered permanent VPS runner CI, independent privacy/security, latest-main compatibility and explicit human approval are release requirements.
