# LightUp Remediation Capacity Studio

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.**

This is an independent offline planning interface, not an assessment, authorization decision, scan, assignment, retest, or deploy. It complements the authenticated remediation Casework PR #1568 without editing its owner's source.

## Start

Open remediation-capacity/index.html from a local checkout with its sibling planner.js, app.js and style.css files. No server, build, installation, database, network, cookie, service worker or browser storage is required.

1. Separately authenticate and authorise export in the existing original LightUp workflow. The canonical CSV header is precisely: finding_id,title,severity,retest_status,remediation. The planner never obtains that report itself.
2. Choose the existing five-column CSV (max 1 MiB, 350 records). Invalid UTF-8, CSV quoting, extra fields, duplicated source IDs and unknown enum values are refused. Supported severities: critical, high, medium, low, info. Original retest states: not_tested, fix_pending, fixed, regression.
3. Enter your own assumptions: 1–30 engineers, 1–5 days/week, 1–10 hours/person/day, 0–80% incident reserve, 1–12 weeks and 1–200 estimated hours for each severity. These are examples, never SLAs.
4. Generate a priority proposal: reported regressions first, then critical → high → medium → low → info. Work spans weeks when needed. Capacity is never exceeded and unplanned backlog is shown.
5. Review anonymous per-week allocations. Export private aggregate CSV/JSON and print a non-authorizing brief. No source finding ID, title, remediation, hostname, address or customer name is included in the exports.
6. Select Forget source & plan or close the tab. No persistence is used; original CSV remains under your own local control.

## Planning model and limitations

Every original retest state remains an unverified work candidate: 'fixed' is not confirmation of completed repairs or independently authorised retest. Available weekly hours = floor(engineers × days/week × hours/person/day × (100 − reserve%) / 100). Highest-priority work consumes integer hours and can continue across weekly buckets. Fully allocated estimated effort is not completed work. The dates are UTC ISO calendar dates, seven days apart, and are not authorised testing windows, actual shift scheduling or booked appointments.

Only aggregate hours, weeks and severity counts are shared. JSON includes explicit false values for authorization, consent, grant, scan, execution, dispatch, verified retest, deploy and release. These local exports are unsigned and carry no identity or authority. Aggregate data still warrants human privacy review.

## Security and release boundaries

- Fatal UTF-8 intake; bounded records/field lengths; strict schema and enums; duplicate IDs fail closed.
- Raw source IDs, titles and remediation text are discarded before scheduling. UI uses text-only DOM rendering, never untrusted HTML.
- CSP denies all network connections and remote scripts. No fetch, XHR, WebSocket, persistent storage, credentials or service worker. Downloads use short-lived local Blob URLs.
- No source alteration, original consent verification, tenant binding, grant issuance, live target action, retest, scan, report mutation or deployment.
- Owner branches, src/lightup/**, workflow, runner, existing security gates and tests are untouched.
- Existing hosted and permanent VPS exact-head CI, real separately authenticated client/operator consent and at-use revocation, independent security/privacy review and explicit HUMAN GO remain mandatory before any release. Do not merge/deploy while DRAFT/HOLD.

Related separate owner: https://github.com/Zennay/Lightup/pull/1568
