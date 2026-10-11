# LightUp M3/M7 — opt-in tenant-selected Unicode finding CSV (W3)

**DRAFT / HOLD, lab-only, never installed.** Builds on the existing opt-in
presentation gate in [PR #1183](https://github.com/Zennay/Lightup/pull/1183),
issue [#1182](https://github.com/Zennay/Lightup/issues/1182); isolated
tenant-adapter acceptance [#1184](https://github.com/Zennay/Lightup/issues/1184).

## What works

`render_tenant_findings_csv_checked(store, authenticated_ctx, client_id,
engagement_id=...)` uses the existing canonical `DomainStore` tenant-scoped
selectors, checks client/engagement lineage and exact contexts, projects only
the fixed `Finding` summary fields, then invokes
`render_findings_csv_checked` once for the entire selected batch. A later
Unicode/field-limit validation failure produces **no partial CSV result**.
The result contains neither targets nor raw evidence and uses the original
CSV redactor and ASCII formula escape for valid values.

It has no external dependencies, no additional database writes, no active
security checks, no model calls, no target network, no remediation or retests.
Unit tests run with a disposable local SQLite `DomainStore` and invented
tenants/findings only.

Run locally:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_finding_export_tenant_checked_20261011_w3.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Ownership and hard limitations

- This function does **not** authenticate callers and must accept contexts
  only from trusted current login/session authority. The tests create synthetic
  contexts to model the expected role behavior, not to authorize real use.
- It **duplicates the canonical source service's selection checks** to avoid
  modifying files currently owned by #960–#965/#1068. Before promotion, owners
  should refactor shared selector selection and inject the checked renderer,
  not maintain two divergent authorization routines.
- Selection and related ownership reads are not an atomic pinned snapshot of
  concurrent tenant database mutations or session revocation. Default read
  API behavior remains unchanged. Trusted session-at-action-time, privacy
  review and evidence-source provenance still need separate owner review.
- Only Unicode presentation integrity is checked, not true spreadsheet-client
  safety, secret-redaction completeness, verification of a finding, proof of
  remediation, availability or retest success.
- Existing CLI, web, `finding_export_service.py`, `finding_export.py` and
  canonical `DomainStore` are untouched. Opt-in function is **not wired**
  to default export, UI, API, job queue, deployment, or authorization.
- **HOLD until original source owners, independent privacy/security review,
  exact-head hosted + genuine permanent VPS CI, and end-to-end verified
  installed authenticated ingress acceptance.** No merge or deploy.

## Acceptance checklist

- [x] Controlled read-only tenant/engagement selection with real disposable
  SQLite, cross-tenant denial, good international text and normal escaped ASCII
  formulas.
- [x] Source-corrupt Unicode formula + compatibility characters denied before
  final serializer, even when another selected finding is valid.
- [x] Synthetic legacy default exporter demonstrably not yet gated, preserving
  an explicit integration blocker.
- [x] Bad identity, context types, corrupt enum and oversized field rejected.
- [ ] Original source owners integrate without duplicate authorization logic.
- [ ] Independent reviewer validates source, privacy, ingress and live-session
  revocation, plus all exact-head permanent runner proofs.
