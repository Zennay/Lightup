# LightUp · PRIVATE HUMAN Follow-up Calendar

**Current release fence: INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.**

This is a complete, **offline human-only** scheduling companion for already-produced [LightUp PRIVATE Assessment Briefing](https://github.com/Zennay/Lightup/pull/1672) seven-column `human-followup.csv` worksheets. Original assessment source owner [#1608 / #1610](https://github.com/Zennay/Lightup/pull/1610) and review [#1637 / #1639](https://github.com/Zennay/Lightup/pull/1639) remain unchanged. The calendar never executes an assessment, calls a target, models findings, grants permission, claims a verified vulnerability, or changes original findings.

## Open and operate

**Preferred:** download [`standalone.html`](standalone.html) and open locally in a modern browser supporting WebCrypto. One file, no installation, server, network or remote assets. Its inline JavaScript and CSS have their exact SHA-256 hashes pinned in the CSP; all remote and form connections are denied. Alternatively keep `index.html`, `app.js`, `style.css` beside each other and open `index.html`. Both versions run entirely in memory; no localStorage or cookies.

1. Import an **original-format HUMAN-only CSV**, limited to 1 MiB / 2,048 original ordinals. Exactly these seven ordered headers are accepted: `original_ordinal,source_reported_severity,evidence_reference_count,human_stage,human_owner_group,human_next_action,human_blocker`. Ordinary quoted CSV/CRLF and strict UTF-8 supported. Invalid row membership, duplicate/missing ordinal, unsupported literal, suspicious HUMAN formula prefixes, overlength text and malformed CSV reject the **entire** input, preserving the current workroom.
2. Search/filter by self-reported severity, HUMAN stage, human group or action; assign an individual date/time, duration (15/30/60/90 minutes), and optional reminder (none/15 min/60 min/one day).
3. Confirm a bulk change only for *currently filtered rows*, or choose **Suggest weekday reminders** to put *filtered unscheduled, non-blocked HUMAN rows* into bounded future weekday slots with existing planned dates protected. Suggestions are ordered by **unverified source-reported severity**, not an independent risk decision; confirm then review dates.
4. Save a PRIVATE **source-bound plan CSV**. The plan contains one ordinal per original source row, and binds to SHA-256 of the **exact human worksheet bytes**, plus your IANA timezone and every schedule field. Reopening the **same** worksheet and importing the plan admits all rows atomically, rejecting different source bytes, swapped/missing ordinals, unknown enum/timezone, invalid dates, or inconsistent rows. It does **not** authenticate the source or amend the HUMAN worksheet.
5. Export local tentative **PRIVATE iCalendar VEVENTs** (`.ics`) only after explicit disclosure confirmation. By default event titles are anonymous original ordinal numbers and descriptions contain self-reported severity and HUMAN stage (already private). Optionally include HUMAN action text after selecting the disclosure checkbox; original lab-source target, evidence, scenario, run and client fields are not imported into this app; however HUMAN-authored text can itself mention confidential clients, targets or evidence, so inspect any opt-in event descriptions before disclosure. Includes per-event reminders and `TENTATIVE` / `REVIEW_ONLY` markers. Dates are interpreted in the *local timezone shown on screen*, then emitted as UTC; daylight-saving ambiguity depends on the local operating-system timezone resolver.
6. Optionally export counts-only JSON with literal-false authentication/authorization claims, **no** source ID/hash, human names or text. Even small aggregates remain PRIVATE.

The bulk-date action schedules every selected row at the **same** specified time (which can deliberately create overlapping events); use weekday suggestions to distribute reminders across days and review the plan.

The planner **does not connect to a calendar**: importing the exported `.ics` into Outlook, Google Calendar, etc. is a separate deliberate human step, with whatever privacy rules that calendar provider applies. There is no attendee, target or remote notification. Calendar sync may disclose metadata; use a private, approved calendar only.

This is deliberately a *source-free, HUMAN-only* interface. It is **not** a substitute for reopening the independently obtained original PRIVATE lab JSON plus unsigned manifest in the original `human_return.py` before treating any worksheet as an actual original-source-bound handoff. A worksheet SHA-256 is a byte identity hint, not a signature, a verified person, client consent, accepted asset scope, authorization, or successful security remediation.

## Building the standalone artifact

```sh
python3 assessment-followup-calendar/build_standalone.py
# Rebuild a pre-existing generated artifact explicitly:
python3 assessment-followup-calendar/build_standalone.py --replace
```

Builds an exact, deterministic one-file HTML (only source HTML/CSS/JS), hashes actual inline text bytes for the CSP, uses an exclusive private temporary file, and atomically publishes. This is **production asset preparation only**, not a QA/test suite. No live target/network/prod use.

## Security and ownership boundary

- Source admission is strict and byte-bounded; no original JSON evidence, actual endpoint, network, model, token, login, cookie or permission is required or supported.
- Import or rejection never overwrites prior original files. Schedule state is held only in browser memory; downloads are explicit. Any tab close without saving loses work.
- The standalone is useful on an authorized offline device but does **not** independently prove browser security/privacy or proper downstream calendar access control.
- This new-only path is a **separate companion**, not a modification to the original source, assessor, owner-owned reviewer or parallel PR. No existing source, CI, webapp, scanner, policy, authorization, test or runner path is modified.
- This release remains **DRAFT/HOLD. DO NOT MERGE OR DEPLOY** until the original exact-head hosted and permanently named self-hosted VPS CI, original source-owner approval, independent security/privacy/browser review, original #177/#182/#829 resolution, actual separately authenticated current client and operator consent including action-time revocation, and **explicit HUMAN GO** are all proven. No active target operations.

No QA, regression or testsuites are added or run as part of this change. Local production script syntax and asset generation can be inspected without waiving any release gate.
