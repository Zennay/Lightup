# LightUp #881 — elevated grant issuance requires same-engagement step-up (offline acceptance)

**Status:** INCUBATE M3/M7; PLAN/LAB ONLY; strictly DRAFT/HOLD/NO MERGE/NO DEPLOY. Independent tests/docs on current `main`; source owners #133/#146 (risk approval), #177 (request/grant provenance), #107 (executor live authorization), and `src/lightup/domain.py` unchanged. Separate older `chatgpt/scope-authorization-elevated-grant-stepup-red-20261007` branch left untouched.

## Exact missing boundary

The current `DomainStore.record_authorization_grant` checks that the issuing actor is an operator, then persists `scope.max_risk`; it does **not** require a current durable `ApprovalStatus.APPROVED` step-up record bound to the **same engagement** and covering the elevated grant's `RiskLevel`. Risk 4/ELEVATED must not be activated from the existence of an unrelated approval, a pending/denied decision, or ordinary operator role alone. This is an admission integrity defect, not evidence of a real customer exploit.

## Real producer acceptance (synthetic only)

New `tests/test_scope_881_elevated_stepup_issuance_independent_20261012.py` creates three engagements (two under one synthetic tenant, one under another) using genuine `DomainStore` and disposable SQLite, with loopback literal `127.0.0.1` as **inert metadata**, no traffic. Controls cover STANDARD grant without step-up, approved ELEVATED step-up in same engagement, and a prohibition on one operator approving their own requested step-up.

**Eight intentional `@expectedFailure` gates** express currently unsatisfied authorization invariants for elevated issuance: no decision; pending; denied; approved under another engagement for the same client; approved under a different tenant; and approved at lower risk than the requested ELEVATED scope. The initial six denials must leave `authorization_grants` empty. Two additional refusals are exercised **after a valid STANDARD grant already exists**: a pending elevation and an unrelated cross-tenant approval must preserve the complete prior grant-row snapshot as well as every approval row (no partial extra authority). Positive controls with real independently-approved same-engagement step-up must retain compatibility; STANDARD grant issuance stays available even with a pending or denied risk-elevation request, and an approved step-up must not be mutated merely by issuing a grant. None of these expected failures proves a repair.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_881_elevated_stepup_issuance_independent_20261012.py' -v
```

## Owner-only integration and release gate

Grant-issuance/source owner must implement a transactionally consistent same-engagement and approved-risk selection before insertion, including decision revocation/staleness and concurrent review/issuance races. The reviewer must verify effective tenant, engagement, reviewer separation, approved ceiling, grant insertion atomicity, risk-5/lab-only behavior and #177 request approval provenance independently. After repair, remove the expected-failure decorators **only when all eight gates pass as ordinary GREEN**. Re-run full current-main compatibility checks.

Require exact SHA GitHub-hosted Python 3.11 and 3.14 unit + real producer integration, independent privacy/security/tenant signoff, separately registered **permanent self-hosted VPS** LightUp CI, and explicit human authorization before merge or deployment. No grants issued outside temporary SQLite, no scanning, real target, browser, DNS, network or code modification of active source owners. Keep [issue #881](https://github.com/Zennay/Lightup/issues/881) OPEN pending integrated proof.

## W2 append-only review observations

Five new real-producer tests (three positive + two expected-RED) characterize the unchanged production issue without modifying current grants or approval code. The W2 failure tests assert **whole-row persistence atomicity** rather than just a zero-row table after denial: previously issued STANDARD grants must survive and cannot silently be promoted by a cross-tenant or pending decision. Any GREEN CI report that still counts expected failures must be labeled diagnostic, not remediation.

## W3 — non-authorizing step-up snapshot reference (NOT INSTALLED)

Two new strictly tests-only paths supplement existing direct-producer expected-RED canaries:

- `tests/scope_881_stepup_snapshot_reference.py` is a **pure, non-authorizing** typed reviewer for a caller-supplied immutable tuple of actual persisted `RiskApprovalRecord` objects. It matches exact client and engagement identities, an explicit independently APPROVED review and a risk ceiling that covers ELEVATED; it refuses malformed/polymorphic snapshots and ALL risk-5/lab-only requests. It returns only `None`, **never a signed or executable grant**.
- `tests/test_scope_881_stepup_snapshot_reference_20261012.py` exercises 12 real disposable SQLite `DomainStore` scenarios: STANDARD without step-up, approved same engagement, pending/denied, other engagement/tenant, lower risk, foreign approved + local pending, same engagement denied then approved, malformed evidence, risk-5 denial and noncanonical context. The snapshot reference itself does not insert any authorization grants or make network calls.

**Critical limitation:** caller-supplied approval tuples are NOT automatically trusted; anyone can fabricate one. These tests are an offline reference ONLY. No actual grant INSERT is performed under the same SQLite transaction as the check, so it **cannot prove atomic grant issuance or avoid TOCTOU/revocation races**. The original `DomainStore.record_authorization_grant` can still mint elevated authority and all eight real-producer RED canaries must remain RED until the source owners implement a trusted transactionally consistent integration. None of this is a release endorsement.
