# Operator Authorization Readiness Desk

**INCUBATE / PLAN-LAB ONLY / DRAFT-HOLD · REVIEW_ONLY · NO EXECUTION AUTHORITY**

An authenticated LightUp operator can now produce a real, local **assessment/grant readiness dashboard** from the existing domain database. It is not a grant, review approval, consent signature, release certificate or repair of source defects [#177](https://github.com/Zennay/Lightup/issues/177) and [#829](https://github.com/Zennay/Lightup/issues/829).

## Delivered workflow

- HTML dashboard: per-client/engagement queue, assessment request and approval counts, stored grant counts, time-window labels and concrete operator follow-up steps.
- JSON report for incident/project tracking, explicitly marked REVIEW_ONLY with every consent/grant/scan/release boolean false.
- CSV operator action register with a row per stored grant (or a no-grant row), concrete follow-up, review flags, tenant and engagement. Spreadsheet formula-prefix values and embedded control characters are neutralized; raw scope hosts, approval references and grant IDs are never included.
- One read-only SQLite transaction using mode=ro and query_only=ON; normal DomainStore login bookkeeping may occur during authentication but assessment data is never mutated.
- The desk also checks stored current-role provenance: the submitted request must point to a same-tenant client member/admin, the reviewer must point to a different persisted operator, and the recorded administrative decision must predate grant creation. It highlights UNTRUSTED_APPROVED_REQUEST_ORIGIN and INVALID_GRANT_CREATION_TIME. This is conservative corroboration; changing current user roles cannot retroactively authenticate past consent.
- Every grant is flagged UNBOUND_APPROVAL_REQUEST because the original schema has no immutable approved-request→grant binding. Even if an approved request has a matching tenant, conservative literal/strict-CIDR asset subset and risk, that is not authorization.
- Additional warning classifications: TENANT_LINEAGE_MISMATCH, NO_COMPATIBLE_APPROVED_REQUEST, AMBIGUOUS_APPROVED_REQUEST_MATCH, INVALID_GRANT_ASSETS, INVALID_GRANT_WINDOW and EXPIRED_GRANT_WINDOW. Orphan grant count appears in the JSON summary.
- Reports omit actual scope hosts/IPs, approval references, passwords and grant IDs. Client and engagement names are included to make the private operator report actionable.

## Run locally

From a LightUp checkout:

    mkdir -m 700 -p /path/to/private-reports
    PYTHONPATH=src python -m lightup.authorization_readiness_cli \
      --db /path/to/existing-lightup.db \
      --email operator@example.com \
      --output /path/to/private-reports/readiness.html

For a tenant-minimized report, add --client-id with the exact existing client ID. Add --engagement-id to further restrict to one job; a specified engagement must belong to the selected client. Tenant-incoherent grants are still checked by the owning engagement ID so bad duplicated grant.client_id fields cannot hide them. A selected client or engagement must exist or the export fails closed.

Use a fresh filename ending in .json for structured machine-readable output or .csv for a spreadsheet-safe action queue. Every CSV record is labelled REVIEW_ONLY and cannot serve as a grant or consent record. The password is requested **interactively** through the original authentication layer; passwords cannot be supplied as CLI flags. Only a persisted real operator account may export. Non-interactive and unauthenticated use fails closed.

**Interactive HTML action workspace:** Open the private .html export locally. Its embedded JavaScript runs strictly in-browser under an exact nonce-based CSP with no network, storage, external library or backend. Search and severity-filter actual stored findings; set owner/team, ticket, follow-up date, private notes and escalation status per case. Assign filtered unassigned issues or escalate filtered unresolved issues in bulk, see overdue local actions, then save your action plan as a bounded JSON file or export a formula-safe CSV of filtered actions. Imported action plans must match the **exact original source fingerprint**, have exactly the expected case IDs, bounded field schema and literal false consent/grant/scan/release flags. Files from a changed database snapshot are rejected; nothing overwrites source findings. Local status 'locally documented' only means operator notes were written, never that a grant or vulnerability has been remedied. No automatic browser persistence; export your work before closing.

**Packaging:** setuptools explicitly includes authorization_casework.js in the LightUp wheel so the installed CLI and checkout CLI can render the same self-contained HTML.

An output path must not already exist. Created report files use mode 0600 and no-follow flags where available. No browser network request, external scripts, target requests or cookies: the HTML contains one nonced offline operator-workspace script with a restrictive CSP. Each inspected table is bounded to 3,000 rows, and output to 2 MiB; oversized sources HOLD rather than produce misleading partial reviews. Retain files locally, do not serve publicly.

## Reading the results

**Tenant mismatch:** treat the record as potentially corrupt and require #829 source-owner lineage read fix before client exposure. Report never alters it.

**No matching approved request or ambiguous matches:** reconcile the *authentic client-origin* approved request, exact intended asset set, mode and risk through the #177 source-owner workflow. This dashboard never issues or approves grants.

**Unbound request:** even one apparently compatible request cannot demonstrate approval provenance because the current domain does not persist request identity on grants. A within-window grant is likewise not an execution authorization.

**Expired or malformed window:** requires source-owner inspection, and cannot be reclassified to authorized by this static report.

## Boundaries and pending gates

This branch only adds the isolated operator Python/JavaScript/docs files plus a non-runtime setuptools package-data declaration in pyproject.toml. It does not touch domain.py, webapp/app.py, studio/ (#1567), guarded portal (#1566), remediation casework (#1568), runners, workflows, tests, authorization gates or deployment configuration. Remaining required gates: domain #177, source-owner #182 and #829, canonical original hosted+permanent registered VPS CI, independent security/privacy approval, genuine separate client/operator consents with at-use revocation and explicit human GO.

**No merge, deploy, grant, scan, active dispatch or release** from this review-only module.