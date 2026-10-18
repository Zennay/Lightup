# LightUp Remediation Capacity Studio

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.**

This is an independent offline planning interface, not an assessment, authorization decision, scan, assignment, retest, or deploy. It complements the authenticated remediation Casework PR #1568 without editing its owner's source.

## Start

**Recommended:** download and locally open [standalone.html](./standalone.html). It is a self-contained HTML with SHA-256 CSP-pinned inline JavaScript and stylesheet. To reproduce it, run Python 3: python3 remediation-capacity/package.py. The digest is a build fingerprint, NOT a signature or authority receipt.

Alternatively open remediation-capacity/index.html from a local checkout with its sibling planner.js, draft.js, app.js and style.css files. No server, build, installation, database, network, cookie, service worker or browser storage is required.

1. Separately authenticate and authorise export in the existing original LightUp workflow. The canonical CSV header is precisely: finding_id,title,severity,retest_status,remediation. The planner never obtains that report itself.
2. Choose the existing five-column CSV (max 1 MiB, 350 records). Invalid UTF-8, CSV quoting, extra fields, duplicated source IDs and unknown enum values are refused. Supported severities: critical, high, medium, low, info. Original retest states: not_tested, fix_pending, fixed, regression.
3. Enter your own assumptions: 1–30 engineers, 1–5 days/week, 1–10 hours/person/day, 0–80% incident reserve, 1–12 weeks and 1–200 estimated hours for each severity. These are examples, never SLAs. For every planning week, independently enter 0–100% availability (default 100%, 0% for holidays/leave/outages), not an authorised testing window.
4. Generate a priority proposal: reported regressions first, then critical → high → medium → low → info. Work spans weeks when needed. Capacity is never exceeded and unplanned backlog is shown. The new priority-band view shows each severity's original regression count, estimated effort, allocated hours, outstanding hours and latest fully planned week; no displayed allocation is a verified fix.
5. Review anonymous per-week allocations. Compare baseline vs 0–10 additional engineers and see the smallest modelled team (up to 30) that fits the estimated work within the chosen horizon. This is hypothetical, not a staffing recommendation, authorised timeslot, task assignment or delivery guarantee. Export private aggregate CSV/JSON/Markdown and print a non-authorizing brief. No source finding ID, title, remediation, hostname, address or customer name is included in the exports.
6. **Historical workload review:** optionally choose an older original, separately authorised five-column CSV and explicitly attest both exports refer to the same real client and engagement. The application cannot authenticate the assertion. It re-reads both locally, compares exact original records by finding ID without preserving raw IDs in its returned result, and reports aggregate added/changed/absent/unchanged counts and estimated hours. *Absent never means verified fixed*. The review is invalidated when a new source or effort plan is loaded. Export a separate, unsigned privacy-minimal comparison JSON after a second explicit confirmation.
7. Select Forget source & plan or close the tab. No persistence is used; original CSV remains under your own local control.

## Source-bound private save and resume

The app now supports **Save private working draft** / **Reopen private draft**. Generate a plan from an already-authorised original CSV first, then deliberately download an unsigned `lightup.remediation_capacity_working_draft.v1` JSON file. Only the team's numeric effort/staffing settings, weekly availability, selected what-if staffing count, input row count and SHA-256 of the **original CSV bytes** are saved. No original finding IDs, target names, client/tenant identifiers, report descriptions, note contents, historical source or simulated permission values are saved.

To reopen, reload the original CSV in the source import control **before** selecting the draft. Restoration requires WebCrypto SHA-256, exact original byte digest, exact row count, strict 8-KiB canonical JSON, exact field/primitive types, literal `review_only:true` and false grant/consent/authorization/scan/execute/dispatch/retest/deploy/release flags. Duplicate keys, whitespace-altered envelopes, unexpected fields and mismatched source fingerprints fail closed. Only after all checks does the app apply the saved options and reconstruct the proposal. Historical comparisons and user-confirmed client/engagement statements do **not** carry over; the operator must separately authenticate the source and confirm current permissions.

This digest is a **local consistency binding**, NOT proof of genuine client identity, authentication, scope consent, revocation, production permission or recovery. The JSON can be modified and isn't signed. Nothing is auto-restored from cookies, localStorage or cloud storage; treat the saved draft as private planning data.

## Planning model and limitations

Every original retest state remains an unverified work candidate: 'fixed' is not confirmation of completed repairs or independently authorised retest. Base available weekly hours = floor(engineers × days/week × hours/person/day × (100 − reserve%) / 100). Each week's actual modeled hours = floor(base weekly hours × that week's availability% / 100), and a 0% week carries its backlog into the next week without silently claiming work. Highest-priority work consumes integer hours and can continue across weekly buckets. Fully allocated estimated effort is not completed work. The dates are UTC ISO calendar dates, seven days apart, and are not authorised testing windows, actual shift scheduling or booked appointments. If any item of a severity remains unallocated, the displayed last-allocation week is unavailable rather than a misleading completion promise.

Only aggregate hours, weeks, severity counts and each week's non-sensitive availability percentage are shared. Historical comparison returns aggregate changes only; the original identifying rows remain temporary inside the local comparison call and are not included in exported metadata. The human-readable Markdown briefing adds explicit discussion prompts for independent client/engagement review and separately verified fixes; it contains no original finding identities. JSON includes explicit false values for authorization, consent, grant, scan, execution, dispatch, verified retest, deploy and release. These local exports are unsigned and carry no identity or authority. Aggregate data still warrants human privacy review.

## Security and release boundaries

- Fatal UTF-8 intake; bounded records/field lengths; strict schema and enums; duplicate IDs fail closed.
- Raw source IDs, titles and remediation text are discarded before scheduling. UI uses text-only DOM rendering, never untrusted HTML.
- CSP denies all network connections and remote scripts. No fetch, XHR, WebSocket, persistent storage, credentials or service worker. Downloads use short-lived local Blob URLs.
- No source alteration, original consent verification, tenant binding, grant issuance, live target action, retest, scan, report mutation or deployment.
- Owner branches, src/lightup/**, workflow, runner, existing security gates and tests are untouched.
- Existing hosted and permanent VPS exact-head CI, real separately authenticated client/operator consent and at-use revocation, independent security/privacy review and explicit HUMAN GO remain mandatory before any release. Do not merge/deploy while DRAFT/HOLD.

Related separate owner: https://github.com/Zennay/Lightup/pull/1568
