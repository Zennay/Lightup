# LightUp Remediation Casework

## Product

An offline client/operator handoff board consuming the **existing authorized LightUp finding-summary CSV** format, without modifying LightUp's domain, authentication, authorization, findings or scanner code.

Open `casework/index.html` from a local checkout in a modern browser. No server, build step, dependencies, external scripts, network, cookies, localStorage or other persistent browser state.

**Workflow:**

1. A real authorized client/operator uses the existing `lightup.finding_export_cli` with its existing interactive authentication, tenant checks and real database. Do **not** use this local page as a replacement for that export.
2. Export the documented five-field summary (in this order): `finding_id,title,severity,retest_status,remediation`. Target identifiers, raw evidence and arbitrary finding metadata are not present in the original export. The shared LightUp redactor is applied by the existing exporter before CSV rendering.
3. Import the CSV locally. The board groups findings by severity, keeps the original `retest_status` read-only and lets operators coordinate a **separate local planning status**, assigned team, due date, next repair action, retest coordination, dependencies and notes.
4. Filter by severity, work stage or search, and sort by risk, due date or title. Dashboard highlights critical/high findings, blocked items, overdue deadlines and items awaiting independently authorized retest.
5. Export an unsigned `lightup.remediation_casework_draft` v1 JSON for resuming the planning session, a spreadsheet-safe CSV **action register** or a Markdown coordination brief. Print the plan if appropriate.

### Refreshing findings without silently copying obsolete status

Load a new authorized CSV into the **Refresh** section while a workspace exists. The page shows how many findings were added, changed, absent or unchanged. Before applying a refresh, an operator must **affirm that both exports really come from the same independently authenticated client and assessment engagement** (the local page cannot verify this statement). Save the old draft before applying.

After explicit confirmation:

- **Unchanged finding records:** retain the existing unverified local owner, due date and remediation notes.
- **New or changed records:** get a fresh, unassigned planning record, avoiding accidental carryover of a prior `retest_status`, mitigation or owner assertion.
- **Absent records:** leave the current view; are **never** interpreted as fixed, retested, removed from the real database or evidence of successful remediation. The previously exported casework JSON still preserves the earlier revision.

### Data contracts and boundaries

- Bounded CSV intake: 1 MiB and at most 350 findings; parser validates RFC4180-style quoting and the exact source columns. Source severities: `info/low/medium/high/critical`; source retest state: `not_tested/fix_pending/fixed/regression`.
- `casework/remediation-engine.js`: CSV parser, source/type normalization, editable case schema, duplicate ID rejection, refresh comparison/reconciliation, summary calculations, local draft contract and spreadsheet-safe action CSV serialization.
- `casework/remediation-app.js`: document-only local UI, import/export handlers, filters, priority, edit controls, update notices, refresh review and Markdown rendering.
- `casework/index.html`: responsive browser UI with all untrusted text inserted with `textContent`; no remote scripts, network calls, active handlers or credentials.
- Exported JSON includes an optional unsigned source SHA-256 (Web Crypto when available) over source finding fields; it is not an authenticated signature and does not confer scope/tenant authority. Import rejects a saved packet if its stored digest conflicts with its own source findings (when hashing is supported).
- The exported JSON explicitly sets `authenticated:false`, `source_authorized:false`, `assessment_authorized:false`, `grant:false`, `client_consent:false`, `operator_consent:false`, `execution:false`, `scan:false`, `retest_verified:false`, `release:false`. No user-entered local `completed` work stage overwrites the original finding's server-side `retest_status` or constitutes verified remediation.
- The CSV action register excludes free-form private notes and retains only selected action/coordination fields. CSV entries beginning with potentially active spreadsheet formulas (even after whitespace/control characters) are prefixed with a quote; all values are fully CSV-quoted. These limits reduce but cannot eliminate accidental sensitive-data disclosure; assess exports before sharing.
- Local CSV may contain sensitive vulnerability details in title/remediation. Files stay in local browser memory; exported drafts may be sensitive and should be exchanged only via an organization-approved authenticated channel. This page never handles evidence capture or target contact.

### Release constraints

LightUp remains **INCUBATE / PLAN-LAB ONLY / DRAFT-HOLD**, with existing hard security/privacy and release requirements. The board is deliberately independent of the default web app owner (#182), approved-request→grant domain owner (#177), tenant-grant lineage (#829), current guarded client/operator clarifications PR (#1566), and browser scope planning PR (#1567).

It is not safe to merge/deploy to the production web app or treat local notes as authoritative before existing hosted CI, permanent registered VPS CI, independent privacy/security review, exact-head owner review, separately authenticated consents with at-use revocation and explicit HUMAN GO. No QA/regression suites were added or invoked as part of this product-only implementation.
