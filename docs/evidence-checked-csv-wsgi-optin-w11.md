# Opt-in checked finding CSV — authenticated WSGI integration reference (W11)

Status: **DRAFT / HOLD / LAB ONLY**. This is an owner-review candidate, not a production entrypoint. It builds upon immutable Unicode/tenant validation parents #1183, #1185, #1186, #1188, #1189 and #1194–#1196. Canonical `main`, default webapp, CLI and source-owner files have not been edited.

## What works in the optional factory

Only explicit Python construction opts in:

```python
from lightup.webapp.finding_exports_unicode_checked import create_app_with_checked_exports
app = create_app_with_checked_exports(store, security)
```

The class inherits the **existing** GET portal CSV routes, authenticated WSGI session and portal checks, existing `WebSecurity` transport/host enforcement, signed-in context, Content-Disposition download, `no-store`, nosniff and CSP/anti-frame response headers. Only `download_findings` is overridden, to call the opt-in `render_tenant_findings_csv_checked` on a session-derived context. Existing application creation, CLI and default CSV renderer remain untouched. The inherited portal link points to that existing URL only **when the optional factory is explicitly constructed**.

The data selection uses existing canonical `DomainStore` tenant/engagement authorization, validates the entire set and snapshot-projected strings before `render_findings_csv` is invoked, retains existing redaction, and excludes raw evidence IDs/target column/metadata. Formula and Unicode integrity failures result in generic 400 and **no partial CSV**; cross-tenant requests are 403; anonymous and revoked sessions redirect to login before data access. No writes other than temporary synthetic test setup.

## What this does NOT establish

- **Not live/installed ingress**: no running Nginx→Gunicorn deployment, TLS, multi-worker concurrency test or real browser acceptance.
- **Not a comprehensive output-sanitization guarantee**: existing redaction recognizes limited secret patterns. Free-text titles/remediation can hold unrecognized sensitive information. Human privacy review is still required before external sharing.
- **Not action-time account authorization proof beyond current inherited WSGI session checks**: revalidation races and identity migration require independent security-owner review.
- **Not a verified remediation, retest, finding or security verdict**. A CSV is a presentation of stored findings, not an authenticity certificate.
- **Not automatically integrated in the actual default portal or CLI**, both intentionally continue using the legacy renderer pending owners.

## Required acceptance before landing

1. Original finding/domain/web/export/ingress owners review the opt-in module and shared selection logic; eliminate duplicated tenant-selector implementation before touching canonical entrypoints.
2. Registered permanent exact-SHA self-hosted VPS CI for this full stack, independent security/privacy tests, actual installed ingress and authenticated Firefox/browser exercise.
3. Merge/rebase coordination with active default-source branches, inspect latest main and conflicts, explicit release approval, no live target actions or real client data.
4. Respect project phase M3/M7 PLAN/LAB only, no active scans, external models, grants, remediation/retest runs, real tenant database changes, merge or deploy.
