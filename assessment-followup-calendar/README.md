# LightUp · PRIVATE HUMAN Follow-up Calendar

**Current release fence: INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.**

This is a complete, **offline human-only** scheduling companion for already-produced [LightUp PRIVATE Assessment Briefing](https://github.com/Zennay/Lightup/pull/1672) seven-column `human-followup.csv` worksheets. Original assessment source owner [#1608 / #1610](https://github.com/Zennay/Lightup/pull/1610) and review [#1637 / #1639](https://github.com/Zennay/Lightup/pull/1639) remain unchanged. The calendar never executes an assessment, calls a target, models findings, grants permission, claims a verified vulnerability, or changes original findings.

## Open and operate

**Preferred:** download [`standalone.html`](standalone.html) and open locally in a modern browser supporting WebCrypto. One file, no installation, server, network or remote assets. Its inline JavaScript and CSS have their exact SHA-256 hashes pinned in the CSP; all remote and form connections are denied. Alternatively keep `index.html`, `app.js`, `style.css` beside each other and open `index.html`. Both versions run entirely in memory; no localStorage or cookies.

1. Import an **original-format HUMAN-only CSV**, limited to 1 MiB / 2,048 original ordinals. Exactly these seven ordered headers are accepted: `original_ordinal,source_reported_severity,evidence_reference_count,human_stage,human_owner_group,human_next_action,human_blocker`. Ordinary quoted CSV/CRLF and strict UTF-8 supported. Invalid row membership, duplicate/missing ordinal, unsupported literal, suspicious HUMAN formula prefixes, overlength text and malformed CSV reject the **entire** input, preserving the current workroom.
2. Search/filter by self-reported severity, HUMAN stage, human group or action; assign an individual date/time, duration (15/30/60/90 minutes), and optional reminder (none/15 min/60 min/one day).
3. Confirm a bulk change only for *currently filtered rows*, or choose **Suggest weekday reminders** to put *filtered unscheduled, non-blocked HUMAN rows* into bounded future weekday slots with existing planned dates protected. Suggestions are ordered by **unverified source-reported severity**, not an independent risk decision; new candidate slots also check the full duration of already planned HUMAN appointments rather than merely matching start times. Confirm then review dates.
4. Open the **Upcoming HUMAN agenda** to see proposed events in date order, with next-7-days, next-30-days, all-scheduled, past-due, or **colliding plans** views and local search. Every event offers **Edit original** to return straight to its full ordinal in the original schedule table. This is an operational HUMAN appointment view, not a confirmed finding or remediation timeline.
5. Review the **HUMAN scheduling collisions** notice: overlaps are detected across local date/time/duration ranges, including overlapping different start times. Explicitly confirm **Propose non-overlapping weekdays** for a bounded 09:00–18:00 weekday reshuffle. It preserves the first appointment and searches free slots without touching the original worksheet or any external calendar. At most 32 conflicting HUMAN appointments are proposed per confirmed operation to keep large workrooms responsive; repeat only if further overlaps remain. It may HOLD if reservations cannot fit in the bounded 90-day planning horizon. It never declares a technical risk or authorization outcome.
6. Open **HUMAN owner workload** to see group-by-group counts for original worksheet entries, unscheduled work, past planned reminders, HUMAN-blocked notes, and overlapping dates. These are HUMAN self-reported group names—not verified operator identity or assignment. Search groups and use **Focus group** to open only that group's original ordinals in the planning table; use **Clear group focus** to return to all. No human name or private group data leaves the browser automatically.
7. Save a PRIVATE **source-bound plan CSV**. The plan contains one ordinal per original source row, and binds to SHA-256 of the **exact human worksheet bytes**, plus your IANA timezone and every schedule field. **New v2 format includes a random private calendar-series ID** (128 bits, opaque, never derived from the original SHA); legacy v1 CSV plans are still admitted in full but receive a fresh event series ID and must be resaved. Reopening the **same** worksheet and importing the plan admits all rows atomically, rejecting different source bytes, swapped/missing ordinals, unknown enum/timezone, invalid dates, or inconsistent rows. It does **not** authenticate the source or amend the HUMAN worksheet.
8. For a separate **encrypted PRIVATE operator handoff**, enter a passphrase of 16–256 characters twice, then choose **Save encrypted PRIVATE plan**. The new `.luhc` binary is `LUHC1\\n` + fresh 16-byte random PBKDF2-SHA256 salt (310,000 iterations) + fresh 12-byte AES-256-GCM nonce + GCM-encrypted exact v2 CSV plan (128-bit tag; fixed domain-specific authenticated associated data). The file remains PRIVATE; its password should be transmitted separately. To restore, open the **same original worksheet** first, enter your password and load the `.luhc`; the entire decrypted plan is re-admitted with exact unsigned worksheet SHA-256, original ordinal ordering, valid timezone and schedule before atomic replacement. On any wrong password, changed worksheet, invalid body or a cancelled replacement, the existing workroom remains untouched. WebCrypto encrypts in browser memory only; no remote API, plaintext intermediate download, key escrow, browser persistence or authorization assertions. Passphrase fields are cleared following import/export, but JavaScript/browser garbage collection and device memory cannot be guaranteed; independent cryptography/privacy review has NOT happened.
9. Export local tentative **PRIVATE iCalendar VEVENTs** (`.ics`) only after explicit disclosure confirmation. By default event titles are anonymous original ordinal numbers and descriptions contain self-reported severity and HUMAN stage (already private). Optionally include HUMAN action text after selecting the disclosure checkbox; original lab-source target, evidence, scenario, run and client fields are not imported into this app; however HUMAN-authored text can itself mention confidential clients, targets or evidence, so inspect any opt-in event descriptions before disclosure. Includes per-event reminders and `TENTATIVE` / `REVIEW_ONLY` markers. **Export only after saving a v2 plan**: a stable per-ordinal ICS UID from the private opaque random series ID is now retained across reloads of the **same exact worksheet bytes**. This avoids minting different IDs each time within the same saved plan, but calendar clients may still duplicate events, and changing the original worksheet bytes requires a new independent workroom; no universal sync/upsert guarantee. Review overlapping reminders before export. The plan itself must be kept PRIVATE to retain these event identities. Dates are interpreted in the *local timezone shown on screen*, then emitted as UTC; daylight-saving ambiguity depends on the local operating-system timezone resolver.
10. Optionally export counts-only JSON with literal-false authentication/authorization claims, **no** source ID/hash, human names or text. Even small aggregates remain PRIVATE.

The bulk-date action schedules every selected row at the **same** specified time (which can deliberately create overlapping events); use weekday suggestions to distribute reminders across days and review the plan.

The planner **does not connect to a calendar**: importing the exported `.ics` into Outlook, Google Calendar, etc. is a separate deliberate human step, with whatever privacy rules that calendar provider applies. There is no attendee, target or remote notification. Calendar sync may disclose metadata; use a private, approved calendar only.

This is deliberately a *source-free, HUMAN-only* interface. It is **not** a substitute for reopening the independently obtained original PRIVATE lab JSON plus unsigned manifest in the original `human_return.py` before treating any worksheet as an actual original-source-bound handoff. A worksheet SHA-256 is a byte identity hint, not a signature, a verified person, client consent, accepted asset scope, authorization, or successful security remediation.

## New PRIVATE publication and HUMAN group handoff

The workroom can reconcile **two copies of its own already-existing v2 plans**, for the **same exact original HUMAN worksheet byte digest, timezone, and opaque private calendar-series ID**. This is useful when a human has already imported a full iCalendar file and must review changes without silently losing removed reminders.

1. Save the original complete PRIVATE `.csv` v2 plan **before** a first manual calendar import. Keep that old file as a history snapshot; this workspace does not automatically write or sync a calendar.
2. Modify the HUMAN reminders locally; save the **new** v2 plan. Both plans must still belong to the **same exact HUMAN worksheet bytes**. No cross-source matching or migration is attempted.
3. In the **PRIVATE calendar change desk**, load the previous saved v2 CSV **or** previous encrypted `.luhc` with its separate passphrase as a **comparison baseline**. The historical encrypted input is decrypted locally with the same bound AES-GCM envelope used for PRIVATE handoff and is never loaded as a replacement for the current plan. Admission rechecks every original ordinal, membership, timezone, SHA and opaque calendar series. All-or-nothing rejection leaves existing current plan intact. The page displays additions, changed times/reminders and removals; no finding or security conclusion is inferred. A failed historical decryption or source/series mismatch does not overwrite either the active schedule or the existing previously selected comparison snapshot.
4. Download a source-bound **PRIVATE change-register CSV** with only original anonymous ordinals, old/new schedule fields, unsigned worksheet SHA and opaque series ID, without original target, finding, evidence or HUMAN description fields.
5. Download added/rescheduled events as a **separate tentative PUBLISH `.ics`**. Download removed events as a **separate CANCEL `.ics`** with the **same stable UIDs** and historical original times. Both require HUMAN confirmation and local manual import to the same authorized calendar. All update/cancel events use conservative `SEQUENCE:1` and no remote API. **There is no guarantee that a provider applies an update, removes an event, or supports repeated multi-revision updates**; users must inspect the resulting calendar manually. Do not infer actual cancellation or security remediation.
6. For separate private HUMAN groups, the **HUMAN owner workload** table offers `PRIVATE .ics` per group. It includes only that group's currently scheduled anonymous original ordinals with the same calendar UIDs as the main export. It requires a saved/restored v2 plan, explicit HUMAN disclosure confirmation and a separate trusted private delivery channel. Group names are unverified original human fields, not authenticated recipients; the user must choose the real recipient separately. Optional HUMAN action text may include highly sensitive information and is off by default.

Both exports are **non-authorizing PRIVATE offline human artifacts**. A SHA digest or calendar series ID is not source authentication, a signature, actual client/operator consent, actual operator identity, grant or proof of verification. Do not import into public or automatically shared calendars. Group calendars and one-step changes do not create persistent sync, cloud appointments or external authorization.

## Group-aware HUMAN capacity planning and private availability handoff

The standalone now contains a complete **offline HUMAN capacity workroom** that is separate from the original assessment-runtime and external calendars:

1. Choose any original HUMAN owner-group label from the already-loaded original seven-column worksheet. Specify that group's proposed maximum appointments per day (1/2/4/6/8/12), local 15-minute-aligned availability window of at least 30 minutes, applicable weekdays, and up to 60 unique unavailable dates (literal `YYYY-MM-DD`). These are only HUMAN-provided planning hints: **not verified operator identity, holiday data, real-life calendar availability, consent or scanning authorization**. Save each group's rule locally; other groups retain their own configuration. The default is Monday–Friday 09:00–17:00 with four proposed appointments/day.
2. Set a start date and a **bounded 14/30/60/90-calendar-day horizon**. The proposer schedules unscheduled, non-blocked original HUMAN ordinals only, capped at **128 human proposals per confirmation**. It distributes work by date/group and source-declared severity order (only an unverified queue sort), obeys the group's weekdays, date blackouts, hours and per-day limit, and refuses candidate time overlaps against already planned or newly proposed reminders in the same source-free workroom. Existing appointments and the source worksheet are not overwritten.
3. Open the exact ordinal-level **read-only proposed schedule table** before confirming. The proposer defaults to **unscheduled HUMAN reminders only**. An explicit mode can propose rescheduling **past-due HUMAN reminders** or a combination of past-due and unscheduled reminders: a prior date is considered past due only if its local scheduled start is before the current clock time. Prior original HUMAN dates are replaced only after the person reviews the exact ordinal-by-ordinal proposal and explicitly confirms the replacement count. Already planned future appointments and HUMAN-blocked rows are never silently overwritten. A past HUMAN reminder date is NOT proof that a security finding is unresolved or that client/operator consent exists. The proposer never connects to Outlook/Google/CalDAV or verifies that staff actually are free. Explicitly confirm to apply the preview to browser memory; any changed plan, source or availability rules invalidates the stale preview, requiring a fresh proposal. Remaining unscheduled ordinals can be scheduled in another explicit batch.
4. Save the complete PRIVATE availability rules to `lightup-private-human-capacity.csv` for a future workroom. This is **not browser persistence**: rules are carried by a user-controlled file with one exact row for every source HUMAN group, sorted, bound to the **exact original human worksheet SHA-256, private calendar series ID and local timezone**. A new source file, series or timezone invalidates the rules. Import is all-or-nothing with validated group membership, canonical hours/days/blackouts and bounded field lengths; failure preserves the current rules and appointments. If the user's v2 calendar series changes upon restoring a different plan, previous local rules are cleared rather than attached to the wrong workroom.

The rules CSV contains original HUMAN group names and blackout dates and is still **PRIVATE**. No signature, verified ownership, source authenticity, assessment authority or calendar deployment is established. More than 256 HUMAN groups, a planning overflow, an invalid rule, or no available bounded slot fails closed; there is no attempt to bypass original release, consent or target gates. The daily limit and collision model are **conservative single-workroom HUMAN coordination rules**, not guaranteed multi-person availability. Only locally proposed appointment dates are changed after confirmation. Use separate manual PRIVATE `.ics` exports for a real human-managed calendar.

## Offline weekly HUMAN coordinator briefing

Select any date and download an optional **self-contained, scriptless, PRIVATE weekly briefing HTML**. It uses the displayed local timezone to collect Monday–Sunday proposed appointments from the loaded original HUMAN worksheet and current local plan. The printable document shows the original anonymous ordinal, HUMAN group, source-reported severity, self-reported HUMAN stage, planned duration/date and summary counts of outstanding, blocked and earlier proposed reminders. By default HUMAN action and blocker text is **omitted**; an explicit checkbox and disclosure confirmation are needed to include them. Human-entered text is HTML-escaped and the resulting file has `default-src 'none'`, `script-src 'none'`, `img-src 'none'` and `connect-src 'none'`, no external styles or scripts, and a bounded total size. A focused HUMAN group can be selected rather than exporting all groups. This does not constitute verified finding status, client/operator authenticity, approval, scope or calendar sync. Use only a privately approved printer/device.

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

### Visual seven-day HUMAN desk (offline)

The same [standalone HTML](standalone.html) includes an interactive Monday–Sunday
calendar board with local date navigation, source-HUMAN group focus, ordinal-to-planner
navigation and filters for literal scheduling overlaps or declared HUMAN availability
mismatches. The board checks each proposed event against the **locally declared**
group weekdays, blackout dates, hour window and maximum appointments/day. It does
not check real people, calendars, source authenticity or consent. Capacity changes
refresh visible warnings immediately without changing existing dates. Every
appointment remains a tentative human-only reminder; use the original row planner
to edit it, and explicitly save the source-bound private v2 plan to preserve it.

### Single-reminder next-slot proposal

Each scheduled week-board card provides **Find next HUMAN slot**. The operator
explicitly confirms one proposed rescheduling; the local search considers at most
31 calendar days, a 15-minute grid, the proposed HUMAN group's declared weekdays,
blackouts, hours and daily appointment cap, and the entire current workroom's
already scheduled (potentially unrelated group) collisions. It never contacts a
calendar, sends a recipient message, changes source data or verifies real-world
availability. Nothing is changed if there is no match or confirmation is declined.
The new local draft is marked unsaved; previously imported events require manual,
separately reviewed PRIVATE calendar update/cancellation handoff.

### Navigating sparse HUMAN calendars

**Next matching scheduled week** and **Previous matching week** skip calendar weeks
without HUMAN reminders rather than requiring dozens of clicks. They respect the
selected HUMAN group and the optional overlap/availability-mismatch filters, and
never change any planned date or export state. If nothing matches, the current
week stays selected. All navigation remains local, in memory and source-free.


### Monthly visual HUMAN calendar

A source-free, offline month overview shows proposed reminders, HUMAN blocked stage
counts and local time-overlap indicators per day. Navigate months, focus a declared
HUMAN owner group and click a date to open the corresponding seven-day planning
desk. This is only a tentative scheduling overview; no external calendar, client,
security result, authority or real-world staff capacity has been verified.


### Offline unscheduled HUMAN queue

All original worksheet ordinals without a locally proposed reminder appear in a
searchable, paginated PRIVATE HUMAN backlog. The HUMAN-blocked stage has its own
visible queue and is never eligible for a one-click time proposal. For each
eligible ordinal, the operator may preview and explicitly confirm a 30-minute
local review suggestion within the next 31 days. The proposer respects declared
group weekdays, time windows, blackouts, appointment cap and every existing
workroom event. Suggestions never contact real calendars, scan targets, send
messages, assert actual human ownership, or claim verified security risk/consent.
Original worksheet and HUMAN fields are immutable. Changes remain unsaved
until the operator explicitly saves the complete source-bound PRIVATE v2 plan.


### Bounded complete HUMAN batch scheduling

The source-free HUMAN queue offers a separate preview for up to twelve currently
filtered, unblocked original ordinals. The local 31-day scheduler reserves each
proposed 30-minute slot against the complete existing and in-flight PRIVATE
plan, respecting declared group weekdays, time windows, blackout days, daily
caps and overlaps. No proposed slot for any selected ordinal means the entire
preview is refused; no partial scheduling occurs. The operator sees every exact
proposed day/time in a separate private table and must explicitly confirm before
the full set changes the local draft. Editing the plan, queue filters, group
policy, source or series invalidates the preview. Manual source-bound v2
save/reopen remains required. No calendar APIs, claims of actual availability,
review status, scan, consent, scope or dispatch.


### Minimum-necessary PRIVATE monthly handoff

The visual month desk can deliberately export a **scriptless local PRIVATE
HTML report** and a separate **daily counts-only CSV** for the currently
selected month and HUMAN-group filter. Explicit confirmation reminds operators
that even small aggregate counts may be sensitive. Outputs include ONLY local
calendar day, proposed HUMAN reminder count, local collision marker count and
self-declared blocked HUMAN-stage count; no source targets, issue identities,
group names, evidence, human notes, source digest, authority, consent or
external recipient. Report CSP prevents scripts and remote resources.
Reports are unsigned local snapshots, not proofs of genuine actions.


### Complete encrypted HUMAN workroom (.luhw)

One PRIVATE local encrypted file now preserves both original-source-byte-bound
HUMAN appointments and the complete declared group policy. The format has a
distinct versioned magic and authenticated AES-GCM context from legacy plan-only
(.luhc) files. The decrypted plaintext uses strict byte-length-delimited UTF-8
plan and capacity CSV sections; both are independently admitted against the
exact original worksheet digest, timezone, series and complete original group
membership before any mutations. Wrong passphrase, mismatch, missing source,
invalid row or malformed file refuses the entire import without replacing
previous data. Explicit user confirmation is required to replace both local
sets atomically. Availability changes trigger a separate unsaved indicator
and unload protection; plan-only export deliberately cannot dismiss it.
The bundle is unsigned as to ORIGINAL SOURCE or identity: passphrase
encryption does not confer real client/operator consent, verified risk,
review completion, live scheduling or scanning authority. No network used.


### Safe legacy plan-only import

Importing a plan-only CSV or .luhc file now explicitly warns before replacing
existing calendar proposals. When an imported plan has a different calendar
series, existing group availability rules would be invalid for the new source
series: the confirmation explicitly announces their reset to defaults and
advises saving the complete encrypted .luhw workroom first. The original
worksheet, current local plan and availability cannot be partially changed
by malformed inputs; source and policy state are rechecked after reading
the file and after the user's confirmation.


### Uncommitted HUMAN group editor protection

Editing a group rule input marks the *form* separately from committed
group settings and the appointment plan. An unload warning covers all
three states; switching groups asks before discarding the uncommitted
form. The complete workroom encrypted export and the separate group-policy
CSV export reject uncommitted group form fields rather than silently
exporting old group hours. The operator explicitly saves the current
HUMAN group rule first. This does not imply real staff acceptance or
verified availability.


### Side-by-side comparison of encrypted HUMAN workrooms

A separate local, password-gated .luhw import now displays appointment and
declared group-policy differences **without** replacing the current PRIVATE
workroom. Both files must admit the same original worksheet bytes and time
zone, and each decrypted section is fully re-admitted under the existing
native browser policy. Differences are strictly HUMAN scheduling data:
original ordinals, local dates, time and durations, and proposed unverified
group availability. The browser lists up to 80 changed entries and provides
a count for the full comparison. Any later change to the current plan,
capacity policy or unsaved capacity editor invalidates and forgets the
previous comparison. The operator can explicitly forget it sooner.
Neither a zero-difference count nor a matching unsigned SHA authorizes
execution, proves consent, verifies findings, establishes owner identity or
synchronizes an external calendar.


### Reviewable whole-workroom differences at scale

The encrypted comparison now offers change-type selection, local ordinal/group
search, and paging over **every** changed appointment or declared HUMAN group
policy (50 per page). Explicit PRIVATE changed-only CSV export is restricted to
the currently filtered entries, with original ordinals and self-reported group
labels, no source findings, targets, evidence or source digest. Spreadsheet-like
formula cells are escaped. Nothing is automatically sent, merged, approved,
authenticated, synchronized with a real calendar or treated as remediation.


### Selective HUMAN reminder reconciliation between encrypted workrooms

After loading two exact-original-source PRIVATE encrypted workrooms, the
operator can individually select up to **32** changed HUMAN reminder ordinals
across filtered/paginated comparison pages. The original private calendar
series must agree. A full explicit preview computes the proposed complete
workroom calendar in memory, checks declared HUMAN group weekdays, hours,
blackout dates and daily caps, and refuses new local overlaps or changes for
source-blocked HUMAN stages. Historical timestamps are not silently copied.
No partial change is applied. The operator must explicitly confirm before
the entire selected set replaces only the corresponding **local HUMAN draft
reminders**. Current group rules, original HUMAN source fields, scanned assets,
security approval and other original appointments remain unchanged. Removing
a reminder in the local draft never cancels a previously published external
appointment; use the existing manual calendar change desk separately.
Any intervening plan, policy, editor or source change invalidates the
comparison and preview. No external calendars, targets or identity providers
are contacted.


### Atomic HUMAN reminder and group-policy reconciliation

The encrypted side-by-side PRIVATE comparison now supports selecting either
original appointment differences or changes to self-declared HUMAN group
availability (up to 32 appointments and 12 group policies). The preview
combines both types into one proposed local workroom, checks all appointments
against the resulting group weekday/hour/blackout/daily-cap rules, refuses
new overlaps and original blocked-stage changes, and requires one explicit
HUMAN confirmation before any local mutation. Group availability changes
cannot trigger any real external staff permission; they are only PRIVATE
planning fields. Both independent unsaved indicators are set appropriately,
and users must manually save a fresh encrypted complete workroom to keep
the combined changes. Source worksheet, client findings, actual grants,
scan permissions, external calendars, previous published reminders and
identity authentication are not changed.
