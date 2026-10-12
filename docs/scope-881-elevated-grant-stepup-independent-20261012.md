# LightUp #881 — elevated grant issuance requires same-engagement step-up (offline acceptance)

**Status:** INCUBATE M3/M7; PLAN/LAB ONLY; strictly DRAFT/HOLD/NO MERGE/NO DEPLOY. Independent tests/docs on current `main`; source owners #133/#146 (risk approval), #177 (request/grant provenance), #107 (executor live authorization), and `src/lightup/domain.py` unchanged. Separate older `chatgpt/scope-authorization-elevated-grant-stepup-red-20261007` branch left untouched.

## Exact missing boundary

The current `DomainStore.record_authorization_grant` checks that the issuing actor is an operator, then persists `scope.max_risk`; it does **not** require a current durable `ApprovalStatus.APPROVED` step-up record bound to the **same engagement** and covering the elevated grant's `RiskLevel`. Risk 4/ELEVATED must not be activated from the existence of an unrelated approval, a pending/denied decision, or ordinary operator role alone. This is an admission integrity defect, not evidence of a real customer exploit.

## Real producer acceptance (synthetic only)

New `tests/test_scope_881_elevated_stepup_issuance_independent_20261012.py` creates three engagements (two under one synthetic tenant, one under another) using genuine `DomainStore` and disposable SQLite, with loopback literal `127.0.0.1` as **inert metadata**, no traffic. Controls cover STANDARD grant without step-up, approved ELEVATED step-up in same engagement, and a prohibition on one operator approving their own requested step-up.

**Six intentional `@expectedFailure` gates** express currently unsatisfied authorization invariants for elevated issuance: no decision; pending; denied; approved under another engagement for the same client; approved under a different tenant; and approved at lower risk than the requested ELEVATED scope. Every denial must leave `authorization_grants` empty. Positive control with real independently-approved same-engagement step-up must retain compatibility. None of these expected failures proves a repair.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_881_elevated_stepup_issuance_independent_20261012.py' -v
```

## Owner-only integration and release gate

Grant-issuance/source owner must implement a transactionally consistent same-engagement and approved-risk selection before insertion, including decision revocation/staleness and concurrent review/issuance races. The reviewer must verify effective tenant, engagement, reviewer separation, approved ceiling, grant insertion atomicity, risk-5/lab-only behavior and #177 request approval provenance independently. After repair, remove the expected-failure decorators **only when all six gates pass as ordinary GREEN**. Re-run full current-main compatibility checks.

Require exact SHA GitHub-hosted Python 3.11 and 3.14 unit + real producer integration, independent privacy/security/tenant signoff, separately registered **permanent self-hosted VPS** LightUp CI, and explicit human authorization before merge or deployment. No grants issued outside temporary SQLite, no scanning, real target, browser, DNS, network or code modification of active source owners. Keep [issue #881](https://github.com/Zennay/Lightup/issues/881) OPEN pending integrated proof.
