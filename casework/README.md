# LightUp Remediation Casework

## Product

An offline client/operator handoff board consuming the **existing authorized LightUp finding-summary CSV** format, without modifying LightUp's domain, authentication, authorization, findings or scanner code.

Open `casework/index.html` from a local checkout in a modern browser. No server, build step, dependencies, external scripts, network, cookies, localStorage or other persistent browser state.

### Recommended: one authenticated export → directly usable offline HTML

In the LightUp repository checkout, on an interactive terminal with an **existing authorized** LightUp database and a real client/engagement, run:

```bash
PYTHONPATH=src python -m lightup.remediation_handoff_cli \
  --db /private/path/lightup.sqlite \
  --email operator@example.org \
  --client-id authorized-client-id \
  --engagement-id approved-engagement-id \
  --output /private/path/lightup-remediation.html
```

The command prompts for the password without putting it in shell arguments. It resolves the current persisted user/tenant role and uses the **same `render_client_findings_csv` service** as LightUp's existing authenticated summary exporter, including engagement ownership checks and source text redaction. It rejects empty, malformed or oversized exports, refuses pre-existing output paths, and writes a brand-new **0600-permission** local HTML file only after the authorized selection succeeds. Use a trusted private local directory; no real target is contacted.

Open `/private/path/lightup-remediation.html` locally. The selected authorized summary is already embedded, all three frontend JavaScript modules are bundled into the file, and a per-file CSP script nonce plus `connect-src 'none'` prevents the generated page from making network requests. No external files or server are required. The generated HTML **contains sensitive finding descriptions in cleartext** and should be protected like a report; transfer only through an approved secure mechanism, not a public URL.

**Authority boundary:** authentication happened at export time only. The resulting portable HTML is **not a signed attestation** and can be modified, forwarded or become stale. It does not prove current client identity, ongoing consent, scope, grant validity, revocation status, retest or remediation. Local assignments never write to the original domain store. Do not host/merge/activate without release approval.

You can still import an existing `findings.csv` manually into `casework/index.html` as described below.

**Workflow:**

1. A real authorized client/operator uses the existing `lightup.finding_export_cli` with its existing interactive authentication, tenant checks and real database. Do **not** use this local page as a replacement for that export.
2. Export the documented five-field summary (in this order): `finding_id,title,severity,retest_status,remediation`. Target identifiers, raw evidence and arbitrary finding metadata are not present in the original export. The shared LightUp redactor is applied by the existing exporter before CSV rendering.

   Typical command from the repository in an authenticated, interactive terminal (substitute your **own** authorized database and client ID; never put a password in command arguments):

   ```bash
   PYTHONPATH=src python -m lightup.finding_export_cli --db /path/to/your/lightup.sqlite --email your-operator@example.org --client-id approved-client > findings.csv
   ```

   The CLI requires a terminal for its password prompt and refuses unauthenticated or unauthorized exports. Never use the command against another customer's data.
3. Import the CSV locally. The board groups findings by severity, keeps the original `retest_status` read-only and lets operators coordinate a **separate local planning status**, assigned team, due date, next repair action, retest coordination, dependencies and notes.
4. Filter by severity, work stage or search, and sort by risk, due date or title. Dashboard highlights critical/high findings, blocked items, overdue deadlines and items awaiting independently authorized retest.
5. Apply a shared owner and/or due date to the **currently filtered subset** using a separate explicit confirmation; other cases are not modified. The browser warns before navigating away while local changes are unsaved.
6. Optionally propose a severity-driven **planning schedule**. Enter a locally agreed planning start date and a separate number of calendar days for critical/high/medium/low/info findings. Preview the list first. Only open cases that lack a due date are eligible; existing dates, deferred cases and completed cases remain untouched. The sample values in the UI are **examples, not contractual SLAs or regulatory commitments**. An explicit confirmation is required before applying.
7. Export an unsigned `lightup.remediation_casework_draft` v1 JSON for resuming the planning session, a spreadsheet-safe CSV **action register** or a Markdown coordination brief. Print the plan if appropriate.

### Refreshing findings without silently copying obsolete status

Load a new authorized CSV into the **Refresh** section while a workspace exists. The page shows how many findings were added, changed, absent or unchanged. Before applying a refresh, an operator must **affirm that both exports really come from the same independently authenticated client and assessment engagement** (the local page cannot verify this statement). Save the old draft before applying.

After explicit confirmation:

- **Unchanged finding records:** retain the existing unverified local owner, due date and remediation notes.
- **New or changed records:** get a fresh, unassigned planning record, avoiding accidental carryover of a prior `retest_status`, mitigation or owner assertion.
- **Absent records:** leave the current view; are **never** interpreted as fixed, retested, removed from the real database or evidence of successful remediation. The previously exported casework JSON still preserves the earlier revision.

### Data contracts and boundaries

- Bounded CSV intake: 1 MiB and at most 350 findings; parser validates RFC4180-style quoting and the exact source columns. Source severities: `info/low/medium/high/critical`; source retest state: `not_tested/fix_pending/fixed/regression`.
- `casework/remediation-engine.js`: CSV parser, source/type normalization, editable case schema, duplicate ID rejection, refresh comparison/reconciliation, summary calculations, local draft contract and spreadsheet-safe action CSV serialization.
- `casework/remediation-schedule.js`: bounded, deterministic UTC calendar-day suggestions, rejecting invalid dates or severity policy and leaving previously scheduled/completed/deferred casework untouched.
- `casework/remediation-app.js`: document-only local UI, import/export handlers, filters, priority, edit controls, update notices, refresh review and Markdown rendering.
- `src/lightup/remediation_handoff_cli.py`: authenticated, tenant/engagement-restricted private one-file browser export using the existing findings summary service and bundled local scripts; no new domain or consent route.
- `casework/index.html`: responsive browser UI with all untrusted text inserted with `textContent`; no remote scripts, network calls, active handlers or credentials.
- Exported JSON includes an optional unsigned source SHA-256 (Web Crypto when available) over byte-stably ordered source finding fields, independent of browser sorting locale; it is not an authenticated signature and does not confer scope/tenant authority. Import rejects any saved packet that claims authority through a required false security flag, or that conflicts with its own stored source digest (when hashing is supported). Overdue counters use the local browser calendar date, while optional severity scheduling uses explicit UTC calendar-day arithmetic to avoid midnight/daylight-saving drift.
- The exported JSON explicitly sets `authenticated:false`, `source_authorized:false`, `assessment_authorized:false`, `grant:false`, `client_consent:false`, `operator_consent:false`, `execution:false`, `scan:false`, `retest_verified:false`, `release:false`. No user-entered local `completed` work stage overwrites the original finding's server-side `retest_status` or constitutes verified remediation.
- The CSV action register excludes free-form private notes and retains only selected action/coordination fields. CSV entries beginning with potentially active spreadsheet formulas (even after whitespace/control characters) are prefixed with a quote; all values are fully CSV-quoted. These limits reduce but cannot eliminate accidental sensitive-data disclosure; assess exports before sharing.
- Local CSV may contain sensitive vulnerability details in title/remediation. Files stay in local browser memory; exported drafts may be sensitive and should be exchanged only via an organization-approved authenticated channel. This page never handles evidence capture or target contact.

### Release constraints

LightUp remains **INCUBATE / PLAN-LAB ONLY / DRAFT-HOLD**, with existing hard security/privacy and release requirements. The board is deliberately independent of the default web app owner (#182), approved-request→grant domain owner (#177), tenant-grant lineage (#829), current guarded client/operator clarifications PR (#1566), and browser scope planning PR (#1567).

It is not safe to merge/deploy to the production web app or treat local notes as authoritative before existing hosted CI, permanent registered VPS CI, independent privacy/security review, exact-head owner review, separately authenticated consents with at-use revocation and explicit HUMAN GO. No QA/regression suites were added or invoked as part of this product-only implementation.
