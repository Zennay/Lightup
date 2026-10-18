# LightUp Offline Assessment Review Desk

**Release boundary:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
Human preparation tool only, not a scan, source authenticity verifier, benchmark release gate, authorization service, consent collection, grant issuance or deployment route.

## Product behavior

Open the generated [standalone HTML](../assessment-review/standalone.html) as a local trusted file. Nothing loads from a network, browser storage API or third-party asset. Choose a local JSON file (max 512 KiB) containing the result of either existing LightUp offline assessment comparator:
- scripts/assessment_runtime_compare_cli_1513.py (single case)
- scripts/assessment_runtime_compare_cohort_cli_1513.py or scripts/assessment_runtime_ground_truth_cohort_cli_1513.py (up to 64 cases)

These producer scripts are actively owned in independent [draft PR #1515](https://github.com/Zennay/Lightup/pull/1515). This desk consumes output **results**, not source scenarios, live records, targets or raw ground truth. Product capabilities: human-prioritized work queue, contextual next-human-action guidance for drift severity and a confirmation-only batch triage action for untriaged regressions, scenario-ordinal labels, all before/after/delta metrics, planning-only follow-up states and dates, filters, local CSV/JSON handoffs with static non-executing suggested follow-up actions in CSV, browser-supported source file SHA-256 a complete print-ready all-case briefing and an optional iCalendar VTODO export for dated open follow-ups. The calendar contains only ordinal case labels and human scheduling metadata; it never includes raw scenario IDs, targets, source hashes, actual operator names or evidence. Exports deliberately exclude real scenario IDs, hostnames, clients, operators, source records, assets, model bindings and notes. No localStorage, cookies, IndexedDB or backend; closing/resetting discards state. Download the review handoff before exiting if necessary. **Restore saved review** accepts only a separately exported privacy-minimal human review JSON bound to the SHA-256 of the exact currently imported original lab comparison source. It atomically restores only human stages and follow-up dates after exact comparison/category verification; no imported statuses can alter original metrics or a HOLD verdict. Without browser SHA-256 support restore is disabled. A newly generated/changed source requires independent human follow-up, not silent carryover.

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
