# LightUp Offline Assessment Review Desk

## Current product update · explicit-reference HUMAN date board · 23 October 2026

The offline Review Desk now includes a local date-planning board for existing HUMAN proposals. Choose the **reference day manually**; the application deliberately does not infer "today", overdue severity, reminders or real deadlines from the device clock.

- It classifies all **not-human-reviewed** cases by proposed follow-up day: before the chosen reference, on it, after it, or undated. Human-reviewed labels are counted separately and excluded from the open follow-up board.
- A four-card summary and anonymous case table show counts, proposed dates, HUMAN planning stage and workstream, and source-derived triage priority. Clicking a case selects its existing original-metric detail; original source identities remain excluded.
- **Export date-plan CSV** downloads the same anonymous, date-sorted visible work list with the chosen reference day, regression count, source-declared unknown coverage and four literal false authority flags. It does not contain source case IDs, client identities, staff assignments, original notes, scope details or raw input.
- All-case and filtered printable briefs include the locally selected reference-day summary. Editing a proposed case date now refreshes the entire board and the print summaries immediately.
- Clearing/loading a new report resets the manually selected day. No browser storage, auto scheduling, notification, authenticated SLA, consent or operational action occurs. Neither a before-date label nor a HUMAN-reviewed stage proves an issue is overdue, repaired, safe or approved.

The standalone offline HTML is rebuilt from the exact source and CSP pins; this remains INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.

## Current product update · cross-sectional unknown-coverage distribution · 23 October 2026

The Review Desk now summarizes candidate-side `coverage_unknown` values across the currently imported report: observed-value coverage, count and percentage above zero, total, median, nearest-rank Q1/Q3 and IQR, and minimum/maximum. Missing metric values are excluded from the distribution rather than silently treated as zero.

The same source-reported summary appears in the dashboard, all-case print brief and filtered queue print brief. It is informational uncertainty context only; it does not reclassify regressions, establish actual coverage, prove remediation, or change REVIEW_ONLY/HOLD or any authority flag.

## Current product update · uncertainty-first queue sorting · 23 October 2026

The offline human triage desk now sorts the filtered scenario queue by source-priority order, highest or lowest source-declared unknown coverage, number of source-reported regression flags, or anonymous scenario ordinal. The selected sort applies consistently to the visible queue, filtered print brief, CSV, JSON and scriptless HTML handoff, with deterministic tie-breakers.

Filtered queue JSON is now schema v3 and records the selected sort. Its importer accepts legacy v1/v2 packets under their original validation and priority-order rules, and validates v3 row order before restoring only HUMAN planning fields. Unknown coverage remains an uncertainty signal, not a regression reclassification or authorization signal.

Current standalone artifact: **103,487 bytes**, SHA-256 `033f30b990489eb442fde685d006c5d8cc900c058f246622c04c98fde384ed1e`. It embeds the exact current JavaScript and CSS and pins their hashes in the restrictive no-network CSP.

**Release boundary:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
Human preparation tool only, not a scan, source authenticity verifier, benchmark release gate, authorization service, consent collection, grant issuance or deployment route.

## Product behavior

Open the generated [standalone HTML](../assessment-review/standalone.html) as a local trusted file. Nothing loads from a network, browser storage API or third-party asset. Choose a local JSON file (max 512 KiB) containing the result of either existing LightUp offline assessment comparator:
- scripts/assessment_runtime_compare_cli_1513.py (single case)
- scripts/assessment_runtime_compare_cohort_cli_1513.py or scripts/assessment_runtime_ground_truth_cohort_cli_1513.py (up to 64 cases)

These producer scripts are actively owned in independent [draft PR #1515](https://github.com/Zennay/Lightup/pull/1515). This desk consumes output **results**, not source scenarios, live records, targets or raw ground truth. Product capabilities: human-prioritized work queue, contextual next-human-action guidance for drift severity and a confirmation-only batch triage action for untriaged regressions, scenario-ordinal labels, all before/after/delta metrics, planning-only follow-up states and dates, filters, local CSV/JSON handoffs with static non-executing suggested follow-up actions in CSV, local source-byte SHA-256 (Web Crypto preferred, portable offline fallback for local file contexts) a complete print-ready all-case briefing and an optional iCalendar VTODO export for dated open follow-ups. The calendar contains only ordinal case labels and human scheduling metadata; it never includes raw scenario IDs, targets, source hashes, actual operator names or evidence. Exports deliberately exclude real scenario IDs, hostnames, clients, operators, source records, assets, model bindings and notes. No localStorage, cookies, IndexedDB or backend; closing/resetting discards state. Download the review handoff before exiting if necessary. **Restore saved review** accepts only a separately exported privacy-minimal human review JSON bound to the SHA-256 of the exact currently imported original lab comparison source. It atomically restores only human stages and follow-up dates after exact comparison/category verification; no imported statuses can alter original metrics or a HOLD verdict. Without browser SHA-256 support restore is disabled. A newly generated/changed source requires independent human follow-up, not silent carryover.

## Clickable cohort regression landscape

The review desk aggregates each canonical metric name by number of source-reported regressed cases and shows the affected scenario count in accessible, clickable bars (no raw scenario IDs). Selecting a metric filters the **on-screen** case queue and never changes the underlying file, planner state, saved review, or exports. The panel also shows untrusted informational totals for runtime seconds and reported compute cost, before versus candidate. No score, percentage, visual color or drop in reported errors means a scan may proceed, a security mitigation is proven or an authorization gate passes.

## Human workstream routing (no identity assertion)

Every imported case now has an explicitly local preparation *workstream* field: unassigned, lab runtime, scope/policy review, evidence review or independent review. The reviewer can filter the queue by workstream and manually correct the selected case. Bulk triage of new regressions suggests an appropriate workstream ONLY for previously unassigned cases; no real human, permission or approval is implied. Workstream appears in the privacy-minimal CSV, printable brief and non-inviting calendar label.

Saved human review JSON uses strict v2 schema with only this new enumerated workstream field added to each case. The Restore action remains bound to the exact original source SHA and keeps atomic review-only semantics. Old v1 exports can still be restored, with workstream safely defaulting to *unassigned*; any unknown or malformed v2 workstream is HOLD without partial mutation.

## Source-matched historical drift comparison

With a real offline **cohort** comparison loaded locally, a reviewer can select a second saved cohort-comparison JSON report. The desk requires exactly the same unique scenario identities and all fifteen metric baseline numbers before displaying a comparison; *single-case* output lacks scenario identity and is refused. The second report is not permitted to update original review states or turn a HOLD into approval.

The timeline panel shows metrics newly regressed, metrics no longer flagged **only in the submitted report**, and previously regressed metrics which deteriorated further. Source scenario identifiers are used only for matching and never appear in the UI or comparison CSV. Follow-up CSV includes only ordinal case labels, named metric fields, original/follow-up read-only statuses and literal false authority flags. Changed results are *unverified reports*, not proof of remediation. Failed imports atomically clear the historical panel without changing the primary report.

## Integrity and privacy limits

The parser checks exact result keys and false security flags, supported metric names and types, finite numeric values, derived regression coherence, complete fifteen-field metrics, cohort identity agreement, bounded counts and atomic rejection of bad imports. It does NOT re-run ScopePolicy, independently verify data provenance, or authenticate CLI input. Browser JSON.parse does not prove raw source duplicate-key uniqueness. A file digest is only a byte fingerprint, not a signature or consent proof.

Priority ordering is only *informational*: scope/policy changes first, then finding count issues, then rubric/coverage. Source HOLD remains HOLD regardless of human workflow stage. REVIEW_ONLY conveys zero security authority. Export flags authorized, consent_verified, dispatch_allowed, release_allowed, release_approved and scan_allowed are all literally false.

## Build

Run: python3 assessment-review/build_standalone.py

The standard-library builder creates the standalone from the three local sources and embeds exact SHA-256 CSP hashes. Node syntax check is allowed as build inspection, not a QA run. Standalone has no CDN or runtime external files. Treat printouts and local saved reports as sensitive even with ordinal labels.

**Exclusive new owned paths for [issue #1575](https://github.com/Zennay/Lightup/issues/1575):** assessment-review/index.html, review.js, style.css, build_standalone.py, standalone.html and this document. No production source, active #1515 branch, other source-owner, runner, CI, tests, grants, consents, scanners, webapp or deployment touched.

## Release HOLD

Do not merge this draft into production without original exact-head hosted + permanently registered VPS CI, source-owner integration, independent security/privacy review, genuine separately authenticated client and operator consent with revocation-at-use, and explicit human GO. No production deploy, targets, scans, real grants or dispatch from this product.

## Compare saved HUMAN planning revisions

After loading the exact original report, use **Compare saved review plans** to
select two prior HUMAN planning JSON exports and compare their stage, workstream
and follow-up-date fields without mutating the current workspace. Each file
must independently match the loaded report's exact SHA-256, source kind/status,
case count/order, ordinal, priority, metric-regression categories and false-only
authority fields. Both legacy v1 and current v2 exports are accepted; v1 has no
workstream field and is shown as unassigned.

The output is changed-only, ordinal-based and contains no raw scenario IDs,
filenames, source evidence or private notes. A separate CSV records the changed
planning fields and four explicit false authority flags. A malformed, oversized,
duplicate-key, stale-source or partial plan is rejected as a whole. The compare
does not restore either plan or edit the active review state. The operator's
"prior/current" labels are not authenticated chronology; status, date and
workstream are unsigned HUMAN planning proposals, never proof of remediation,
approval, consent or release.

All local JSON intake now rejects duplicate object keys (including escaped
spellings that decode to the same key) before canonical schema admission. This
prevents ambiguous source or saved-plan fields from being silently resolved by
the browser's ordinary last-key-wins JSON parser.

When the saved-plan comparison is active, **Print brief** includes the same
changed-only planning table and transition totals alongside the complete
current all-case follow-up brief. Clearing the comparison removes its delta
from the print output; the original lab verdict and current plan remain intact.


## Filtered queue handoff

The queue has CSV, JSON and standalone HTML export actions that reuse the exact on-screen status, workstream, informational priority and metric filters. They export only the currently visible cases, in the same informational priority order, with anonymous ordinal labels, source-reported metric names, relevant numeric baseline/candidate/delta values (only the selected metric, or source-flagged metrics when no metric filter is active), local HUMAN stage/date/routing labels and static suggested follow-up guidance. CSV serializes the bounded numeric metric subset as a quoted JSON cell; the JSON handoff uses structured metric objects. The handoff records the selected filters, including the informational priority band, and literal false authorization, consent, dispatch, release, approval and scan flags. CSV cells use the existing formula-prefix guard. Raw scenario IDs, hostnames, client/operator names, source evidence and notes are excluded. An empty filtered view produces no file; the all-case exports remain available separately. This is an unsigned planning handoff, not proof of remediation, identity, permission or release.


## Restore a filtered HUMAN queue from another local review

**Import filtered queue JSON** restores only the included cases' HUMAN stage, workstream and
follow-up date. The import is limited to an exact locally loaded original report byte digest,
source kind and source verdict. It strictly rechecks the export contract, false authority
flags, every included ordinal, canonical source-reported metric fields, filter membership,
priority ordering, dates and uniqueness before applying anything. Duplicate, stale, malformed,
incomplete or altered source-evidence rows cause HOLD with the current plan preserved.

A filtered import is intentionally partial: cases absent from the handoff are left unchanged.
The imported subset must match the filter declarations and canonical queue order; its mutable
HUMAN status/workstream are validated against the saved filter values, not the recipient's
current plan, so a reviewer can receive changes for cases whose local stage has since diverged.
A successful import records the previous HUMAN plan in the existing one-step Undo snapshot.
No original metric, source verdict, note, authorization, consent, dispatch or release state is
imported. This remains an unsigned local byte-binding workflow, not reviewer authentication or
proof that the source report is genuine.

## Standalone filtered HTML handoff

The filtered queue now has a third export format: **Export filtered queue HTML**. It produces
one self-contained, scriptless HTML document containing only the cases matching the current
status, workstream, priority and metric filters. The handoff includes the source-reported
status, anonymous ordinal, local HUMAN stage/date/route, selected metric movements and
suggested next HUMAN action. It includes the unsigned local source-byte digest so the
operator can keep the handoff associated with the exact imported bytes.

The downloaded document has a restrictive no-network/no-script Content Security Policy,
no external assets and no executable code. Dynamic text is HTML-escaped before serialization.
Raw scenario IDs, target names, source paths, private notes and client/operator identifiers
are omitted. Empty filters produce no file. The handoff explicitly keeps authorization,
consent, dispatch, release approval and scan permission false; it is a review aid, not a
signed record or proof of remediation.

## Filtered queue printing

The new **Print filtered queue** action uses the exact current status, workstream, priority-band and metric filters used by the visible queue and filtered CSV/JSON/HTML handoffs. It prints only the matching anonymous case rows plus a plain-language summary of the filters and counts, followed by source-reported baseline/candidate/delta values for each flagged metric and the static suggested next HUMAN action. In this mode the all-case brief, overview cards, historical comparisons, saved-plan delta and selected-case details are suppressed, preventing unrelated cases from being included in a filtered printout. **Print brief** remains the separate all-case report action and retains any active saved-plan delta. Printing changes no review state and exports no raw scenario IDs, hostnames, source evidence or private notes; all statuses remain unauthenticated HUMAN planning only.


### Local source-byte digest availability

The review desk prefers Web Crypto for source-byte SHA-256 and falls back to a portable local implementation when `crypto.subtle` is unavailable in a `file://` browser context. This keeps saved HUMAN review export/restore usable offline. The digest is unsigned local byte binding only: it does not authenticate source origin, reviewer identity, client/operator consent, authorization or release.


## Atomic and non-destructive local review imports

Opening a new original offline JSON comparison first validates the entire bounded canonical report and its local source-byte SHA-256 before replacing the current HUMAN review workspace. An invalid, oversized, incompatible or superseded file **no longer erases** the original loaded report, current HUMAN follow-up stages, print view or source-bound saved plan. Only a successful source replacement intentionally clears old review/history state. Choosing a newer file, pressing Clear, changing a HUMAN follow-up or clearing a saved comparison cancels stale pending local reads.

Likewise, import of a historical follow-up and comparison of two saved HUMAN plans is transaction-like: malformed or stale files cannot replace a previously accepted historical comparison/plan delta. A saved HUMAN follow-up restore is source-byte-bound and rechecks that no newer local user action superseded it before applying any per-case planning fields. No source authenticity, authorization or consent is inferred from this local file workflow.


## Multi-step undo and redo for HUMAN planning

Use **Undo HUMAN change** and **Redo HUMAN change** to move through the last 20 successful local planning edits in this browser session. The history covers workstream, HUMAN stage, follow-up date, bulk triage, filtered-queue restore and source-byte-matched saved-review restore. Snapshots contain only HUMAN planning fields, never source metrics, evidence or report verdicts. Every entry is bound to the currently loaded original source SHA-256; loading a different report or choosing Clear discards both history stacks. Keyboard shortcuts work when focus is outside editable fields: Ctrl/Cmd+Z undoes, Ctrl/Cmd+Y redoes and Ctrl/Cmd+Shift+Z redoes. History remains in memory only; no browser storage is used. These edits never execute assessments or grant consent, release or authority.
