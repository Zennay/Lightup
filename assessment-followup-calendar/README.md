## Optional unbound anonymous count comparison · 23 October 2026

The recipient group desk can now reopen an **earlier own-export anonymous group workload CSV** without any original worksheet, group names, source SHA, appointments or notes. Admission is strict: own-canonical CSV, fixed schema, sequential anonymous group slots, pooled tiny-cohort row only at the end, nonnegative bounded category integers summing to each row's planned total, literal false authority flags, no extra columns/rows, and unchanged current workroom during asynchronous file read and human confirmation. Failure leaves the existing earlier comparison untouched.

A local matrix shows earlier/current **aggregate counts only** for scheduled reminders, declared-hours fit, weekday mismatch, unavailable local dates, and clock-change attention. A separate counts-only CSV contains numeric differences and literal false fields for same-cohort verification, authority, consent and release. There is deliberately no attempt to align anonymous group slots, infer a true longitudinal trend, verify recipient identity or conclude that a removed HUMAN note was fixed. An earlier report can come from a different underlying cohort and is explicitly **UNBOUND**. No persistent browser storage; changing the original source/series clears the prior imported counts, while changing the current HUMAN schedule can be reviewed as a new unverified snapshot.

**Privacy upgrade:** Group exports now pool all tiny source-reported groups with fewer than three proposed appointments into one combined count row. Each export preserves aggregate accounting while excluding these small group slots. This reduces but does not eliminate re-identification risk, so human disclosure approval remains mandatory. A large private workroom remains readable; source group views are still paginated, and exports reject changed original/policy contexts.

## Recipient-group privacy-minimal HUMAN review · October 2026

The alternate-timezone group desk offers an explicit **next group needing HUMAN attention** navigator across groups with proposals outside manually declared hours/weekdays or on unavailable days/clock changes. This focuses existing original ordinals locally; no appointments or source authority are changed.

Two new PRIVATE local exports, explicitly confirmed each time, provide the **entire** already-scheduled cross-zone group workload: aggregate CSV and scriptless printable HTML. Groups are represented only as per-export, nonpersistent anonymous group slots ordered by their own local attention counts. Each includes only planned/within-hours/outside-hours/weekend/unavailable-date/clock-change counts and literal false authority flags. No worksheet hash, group labels, identity, original ordinal, appointment date, free text, target, or recipient address is exported. Small-group counts may still be re-identifiable in context; do not distribute without a separately authorized PRIVATE disclosure review. The export re-admits current recipient timezone and policy, re-computes group counts, and fails closed if the source or HUMAN policy changes while confirming. Invalid recipient zone/window disables exports and navigation; changing/clearing the source removes rendered group data.

**No actual recipient work hours, identity, consent, calendar delivery, scope authorization, security severity or execution has been verified.** No network, external calendar, grant, target, scan or dispatch.

# LightUp · PRIVATE HUMAN Follow-up Calendar

**Current release fence: INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.**

This is a complete, **offline human-only** scheduling companion for already-produced [LightUp PRIVATE Assessment Briefing](https://github.com/Zennay/Lightup/pull/1672) seven-column `human-followup.csv` worksheets. Original assessment source owner [#1608 / #1610](https://github.com/Zennay/Lightup/pull/1610) and review [#1637 / #1639](https://github.com/Zennay/Lightup/pull/1639) remain unchanged. The calendar never executes an assessment, calls a target, models findings, grants permission, claims a verified vulnerability, or changes original findings.

## Open and operate

**Preferred:** download [`standalone.html`](standalone.html) and open locally in a modern browser supporting WebCrypto. One file, no installation, server, network or remote assets. Its inline JavaScript and CSS have their exact SHA-256 hashes pinned in the CSP; all remote and form connections are denied. Alternatively keep `index.html`, `app.js`, `style.css` beside each other and open `index.html`. Both versions run entirely in memory; no localStorage or cookies.

1. Import an **original-format HUMAN-only CSV**, limited to 1 MiB / 2,048 original ordinals. Exactly these seven ordered headers are accepted: `original_ordinal,source_reported_severity,evidence_reference_count,human_stage,human_owner_group,human_next_action,human_blocker`. Ordinary quoted CSV/CRLF and strict UTF-8 supported. Invalid row membership, duplicate/missing ordinal, unsupported literal, suspicious HUMAN formula prefixes, overlength text and malformed CSV reject the **entire** input, preserving the current workroom. A leading UTF-8 BOM is deliberately rejected; the decoder preserves it long enough to fail closed instead of silently stripping it. The same rule applies to imported plan/policy files and embedded text sections of encrypted workrooms.
2. Search/filter by self-reported severity, HUMAN stage, human group or action; assign an individual date/time, duration (15/30/60/90 minutes), and optional reminder (none/15 min/60 min/one day).
3. Confirm a bulk change only for *currently filtered rows*, or choose **Suggest weekday reminders** to put *filtered unscheduled, non-blocked HUMAN rows* into bounded future weekday slots with existing planned dates protected. Suggestions are ordered by **unverified source-reported severity**, not an independent risk decision; new candidate slots also check the full duration of already planned HUMAN appointments rather than merely matching start times. Confirm then review dates.
4. Open the **Upcoming HUMAN agenda** to see proposed events in date order, with next-7-days, next-30-days, all-scheduled, past-due, or **colliding plans** views and local search. Every event offers **Edit original** to return straight to its full ordinal in the original schedule table. This is an operational HUMAN appointment view, not a confirmed finding or remediation timeline.
5. Review the **HUMAN scheduling collisions** notice: overlaps are detected across local date/time/duration ranges, including overlapping different start times. Explicitly confirm **Propose non-overlapping weekdays** for a bounded 09:00–18:00 weekday reshuffle. It preserves the first appointment and searches free slots without touching the original worksheet or any external calendar. At most 32 conflicting HUMAN appointments are proposed per confirmed operation to keep large workrooms responsive; repeat only if further overlaps remain. It may HOLD if reservations cannot fit in the bounded 90-day planning horizon. It never declares a technical risk or authorization outcome.
6. Open **HUMAN owner workload** to see group-by-group counts for original worksheet entries, unscheduled work, past planned reminders, HUMAN-blocked notes, and overlapping dates. These are HUMAN self-reported group names—not verified operator identity or assignment. Search groups and use **Focus group** to open only that group's original ordinals in the planning table; use **Clear group focus** to return to all. No human name or private group data leaves the browser automatically.
7. Save a PRIVATE **source-bound plan CSV**. The plan contains one ordinal per original source row, and binds to SHA-256 of the **exact human worksheet bytes**, plus your IANA timezone and every schedule field. **New v2 format includes a random private calendar-series ID** (128 bits, opaque, never derived from the original SHA); legacy v1 CSV plans are still admitted in full but receive a fresh event series ID and must be resaved. Reopening the **same** worksheet and importing the plan admits all rows atomically, rejecting different source bytes, swapped/missing ordinals, unknown enum/timezone, invalid dates, or inconsistent rows. It does **not** authenticate the source or amend the HUMAN worksheet.
8. For a separate **encrypted PRIVATE operator handoff**, enter a passphrase of 16–256 characters twice, then choose **Save encrypted PRIVATE plan**. The new `.luhc` binary is `LUHC1\\n` + fresh 16-byte random PBKDF2-SHA256 salt (310,000 iterations) + fresh 12-byte AES-256-GCM nonce + GCM-encrypted exact v2 CSV plan (128-bit tag; fixed domain-specific authenticated associated data). The file remains PRIVATE; its password should be transmitted separately. To restore, open the **same original worksheet** first, enter your password and load the `.luhc`; the entire decrypted plan is re-admitted with exact unsigned worksheet SHA-256, original ordinal ordering, valid timezone and schedule before atomic replacement. On any wrong password, changed worksheet, invalid body or a cancelled replacement, the existing workroom remains untouched. WebCrypto encrypts in browser memory only; no remote API, plaintext intermediate download, key escrow, browser persistence or authorization assertions. Passphrase fields are cleared following import/export, but JavaScript/browser garbage collection and device memory cannot be guaranteed; independent cryptography/privacy review has NOT happened.
9. Export local tentative **PRIVATE iCalendar VEVENTs** (`.ics`) only after explicit disclosure confirmation. By default event titles are anonymous original ordinal numbers and descriptions contain self-reported severity and HUMAN stage (already private). Optionally include HUMAN action text after selecting the disclosure checkbox; original lab-source target, evidence, scenario, run and client fields are not imported into this app; however HUMAN-authored text can itself mention confidential clients, targets or evidence, so inspect any opt-in event descriptions before disclosure. Includes per-event reminders and `TENTATIVE` / `REVIEW_ONLY` markers. **Export only after saving a v2 plan**: a stable per-ordinal ICS UID from the private opaque random series ID is now retained across reloads of the **same exact worksheet bytes**. This avoids minting different IDs each time within the same saved plan, but calendar clients may still duplicate events, and changing the original worksheet bytes requires a new independent workroom; no universal sync/upsert guarantee. Review overlapping reminders before export. The plan itself must be kept PRIVATE to retain these event identities. Dates are interpreted in the *local timezone shown on screen*, then emitted as UTC. A spring-forward nonexistent time, autumn repeated (ambiguous) local hour, or appointment spanning an offset transition now **HOLDs before admission**. Move the proposed HUMAN reminder to an unambiguous local hour, then explicitly save and re-export. The browser/OS timezone database remains the local time authority, not a verified recipient calendar.
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


### Group-aware exact conflict-desk handoff

The original local collision resolution button now opens an **exact,
separate HUMAN preview table** of up to 32 changes, before any plan
mutation. It uses the user-declared group weekdays, operating hours,
blackout days and daily appointment caps rather than silently falling
back to global 09:00–18:00 weekdays. Proposed replacements avoid every
original and already proposed appointment in the local workroom.
A source-blocked HUMAN stage, an appointment lacking a valid slot
within 90 days, a newly introduced clash, stale local source/policy or
a group-rule violation fails closed with **no partial edit**. All rows
require explicit confirmation before applying, and external calendar
changes/cancellations remain separate manual work. Overlap status alone
never asserts a vulnerability, unapproved target, verified resources
or human consent.


### Precise original HUMAN blackout-day comparisons

Group policy reconciliation compares canonical **full** rule contents, not
just the number of declared blackout dates. Changing one unavailable day
to another must produce a visible difference even if total blackout count
stays equal. The preview explicitly displays affected local dates.
Unassigned HUMAN group (empty identifier) is kept separate from a literal
self-reported group name that says '(unassigned)'. The private comparison
table and changed-only CSV include only the four intended visible fields;
the exact opaque group key is used solely within memory for unambiguous
selection and never added as an accidental extra export column.


### Review-only conflict proposal handoff

The group-aware conflict desk can export its exact currently prepared
32-row-or-fewer original HUMAN ordinal remapping as a **PRIVATE local
CSV**. It includes only anonymous source ordinal, self-reported HUMAN
group, old/new local reminder dates and times, duration and explicit
REVIEW_ONLY_NOT_APPLIED status. The export requires HUMAN confirmation,
does not apply or dispatch an appointment, and refuses stale input.
Group quota lookups and local occupancy are also cached per original
appointment search; each day within the 90-day proposal horizon no
longer recomputes the entire workroom's original event intervals.
Original blocked-stage conflicts display the precise ordinal instead
of attempting any automatic rescheduling. No original source, risk,
consent or live-calendar verification is inferred.


### Portable original HUMAN workroom — independent original worksheet

The browser also offers a separate **encrypted portable source-and-workroom**
file workflow. The original imported HUMAN-only seven-column CSV bytes remain
in volatile browser memory until replacing or discarding the source (at which
point the previous buffer is cleared). A portable vault is separate from the
older appointment-only and whole-workroom backups and will include the
original source bytes as encrypted content. It is not produced by a network
service, does not assert source authenticity, and requires an explicit
passphrase supplied only inside the local browser. Legacy backups remain
fully supported. A portable vault should be kept on authorized PRIVATE media:
even HUMAN worksheets and group policies can reveal sensitive operations.


### Portable original HUMAN vault export (.luhv)

The original HUMAN-only CSV bytes are now sealed together with the complete
exact-source-bound v2 appointment plan and declared HUMAN-group availability
under a new, disjoint authenticated AES-256-GCM context (PBKDF2-SHA256, fresh
salt/nonce, 310,000 derivation iterations), not interchangeable with old
.luhc plan-only or .luhw no-original backup envelopes. The 1 MiB encrypted
file limit covers **all** bundled content; oversized original worksheet or
plan is refused, never truncated. Source SHA-256 is recomputed over the
byte-exact original in memory before encryption. Export is explicitly
confirmed and creates only a locally downloaded PRIVATE file; it clears
unsaved indicators only after handoff. Neither SHA nor ciphertext constitutes
authenticated producer identity or permission to assess an asset.


### Self-contained .luhv reopen without separate source CSV

Portable encrypted HUMAN vault import is available even when no original
worksheet has been opened yet. It uses a separate authenticated envelope
magic and AES-GCM AAD from both older encrypted backup types. After
decryption, the complete byte-delimited ORIGINAL HUMAN CSV is strictly
parsed, its unsigned SHA-256 independently recomputed, every v2 local
appointment checked against the newly admitted original ordinals,
timestamp/timezone and common private calendar series, and each
original self-declared owner-group policy fully validated. Source,
appointment and policy data are held in temporary state until all three
are admitted, the prior workroom remains unchanged on any error, and
the user explicitly confirms a single atomic replacement. Reopening
restores the source's original HUMAN rows, the entire schedule, all
group policies and private calendar event series without browser
storage or servers. The browser does not authenticate the original
CSV producer, true reviewer identity, actual consent or findings.


### Offline portable-vault passphrase change

Existing encrypted .luhv files may be locally re-encrypted to a **new,
different** 16–256-character passphrase without opening/changing the
current browser planning workroom and without needing the old worksheet
as a separate file. The app first decrypts using the original passphrase,
strictly readmits the complete byte-exact original HUMAN worksheet,
every proposed appointment and every group rule, reserializes both
source-bound components in the same stable series, and applies a new
fresh salt/IV with the existing distinct portable-vault AES-GCM AAD.
Only after explicit human confirmation is a newly encrypted file
downloaded. Old portable files **are not revoked, rewritten or
deleted**, so anyone retaining an old file/passphrase can still open it.
Users must manage rotation/retention outside the browser. No grants,
verified identity, security findings, calendar sync, scan or network use.


### Recover one original component from a portable HUMAN vault

An encrypted portable vault can also be opened **read-only** to recover
exactly one source-bound PRIVATE CSV: the original byte-for-byte HUMAN
worksheet, the original full appointment plan or the complete
self-declared HUMAN group-availability policy. Each export requires
the portable passphrase, full cryptographic decryption plus all
existing strict original-source, series, time-zone and rule admission,
and an additional explicit human disclosure confirmation. Recovering
a component never loads, replaces or changes an existing browser
workroom and never touches an external calendar or assessed system.
The worksheet is recovered from original encrypted bytes, not
regenerated text, to preserve its exact SHA-256 binding; original
HUMAN action/blocker text can be sensitive and belongs only on
authorized PRIVATE storage.

### PRIVATE vault timezone and passphrase lifetime

The original exact worksheet, private calendar series and browser IANA
timezone are preserved together. Opening a portable vault on a device with
a different local zone is deliberately refused; this prevents silent
changes to HUMAN appointment times around daylight-saving transitions.
Resetting the browser workroom and loading a different original worksheet
clear the portable old/new password fields as well as plan handoff inputs.
Encrypted file possession does not establish actual client or operator
consent, and cryptographic review remains an original release prerequisite.


## PRIVATE HUMAN clock-change review

Proposed appointments are now admitted only when the current browser/OS local time is unambiguous: nonexistent spring-forward hours, repeated autumn hours and appointment durations crossing an offset transition fail closed. If the system timezone changes during an open workroom, local time conversion holds until the operator reloads the intended original workroom. The operating system's timezone data is not independently attested.

All existing automatic HUMAN weekday, group-capacity, single-slot and conflict-resolution proposers now skip invalid DST/local-clock slots and look for another admitted time within their existing bounded horizon instead of aborting a complete proposal at the first invalid candidate. They still respect original capacity, source and manual confirmation gates.

The new read-only clock-change desk lists tentative reminders within 12 hours of an OS-reported offset transition. Review individual original HUMAN ordinals, or deliberately download an unsigned PRIVATE source-bound CSV with original worksheet hash, series, timezone, ordinal, unverified group, proposed local/UTC time and explicit false authority/verification/consent flags. Even aggregate HUMAN schedules may reveal sensitive metadata; never share with an unapproved recipient. This tool does not inspect external calendar imports.

## PRIVATE alternate IANA timezone HUMAN handoff

The **PRIVATE HUMAN alternate-timezone preview** accepts a manual browser-supported IANA timezone identifier such as Europe/London or America/New_York and displays the first 35 existing tentative appointments in that zone, with per-original-ordinal navigation. Conversion is read-only, uses the local OS Intl timezone data and does not change the stored source-zone plan, DST admission, event UID or existing calendar export. No network, remote calendar, verified recipient, time-zone proof or consent is involved.

The alternate-zone desk now paginates all matching HUMAN ordinals (35 per page), searches group or ordinal, and lets the operator filter by the manually entered recipient-zone daily window, days outside the declared weekday policy, or the in-window proposals. The default is weekday 09:00–17:00, adjustable in 15-minute increments within 06:00–21:00, with at least 30 minutes; only non-overnight windows are admitted. These values are **HUMAN-declared, unverified**, not an authenticated recipient availability claim. Converted end times include the proposed HUMAN meeting duration. The PRIVATE CSV exports the exact filtered subset, including the neutral illustrative status.

The explicit full owner-private CSV export includes the unsigned original HUMAN worksheet digest, series, original/source and requested display zones, ordinal, self-reported group, original local time, UTC instant, alternate local display and literal false authority/verification/consent flags. It is **not** an anonymous or safe-to-publish export; proposed appointment dates and unverified HUMAN group labels can reveal private work. Recipients must confirm their own actual zone and calendar entry separately.

## HUMAN common-hours adjustment (local preview and explicit apply)

The alternate-zone desk now includes an optional **complete PRIVATE HUMAN draft adjustment**. It only considers the first 12 currently filtered original HUMAN ordinals already scheduled outside the current *HUMAN-declared* recipient weekday/hour window, excludes original HUMAN-blocked rows, and searches for later source-zone slots within a bounded 30-day local horizon. Candidate reminders must pass the existing full local-date/DST admission gate, original declared source-group weekdays/hours/blackout dates/daily caps, no-new-overlap check against all other scheduled local appointments, and the current source-bound HUMAN-declared recipient window for the entire original duration. The whole preview HOLDS if even one selected ordinal has no admissible candidate; there are **no partial edits**.

After preview, the table now offers **individual original-ordinal checkboxes**. Only explicitly selected proposals are included in the PRIVATE, unsigned review-only CSV handoff or eligible for local apply; unselected original appointments remain unchanged. The apply step independently checks that **each selected new interval overlaps no other current or newly proposed event**, so partial selection cannot silently double-book the workroom. There is no review or release attestation in the CSV, and `applied=false` for each exported row.

Selected HUMAN proposals can also be downloaded as a **scriptless, restrictive-CSP PRIVATE HTML review sheet** for local reading or printing on a trusted device. It includes only selected ordinal, prior/proposed source-zone dates, duration, unverified HUMAN group and unsigned source/series binding, plus literal false authority/consent/verification/applied statements. All HTML text is escaped; no external assets, scripts, connection or calendar API are used. The file is confidential, not an approval or verification certificate.

After applying the selected-only draft, a one-step **Undo last HUMAN draft adjustment** is available while the exact in-memory source-bound plan and declared group policies remain unchanged. Undo restores the previous selected reminders only, demands HUMAN confirmation and invalidates itself after the first subsequent workroom edit. It does NOT restore a previously exported external calendar; keep old and new PRIVATE plan versions for manual reconciliation.

A separate visible old/new ordinal table and explicit HUMAN confirmation are required before applying only the **selected ordinals** to the browser-only PRIVATE draft. The proposal is invalidated by source, plan, availability policy, requested IANA zone or filter change; apply re-admits the proposed slots and local constraints and rejects newly created conflicts. Changes set the draft as unsaved and require a new PRIVATE source-bound plan export. Previous .ics calendar exports, externally imported meetings and human recipient agreements are **not** changed or cancelled. The declared recipient window, captured in PRIVATE filtered CSV and scriptless review HTML, cannot establish recipient identity, actual availability, scope, consent, verified urgency or security release.

## HUMAN-declared recipient window (manual, never authenticated)

An operator may edit the target display-zone weekday policy (Monday–Friday or all seven days) and daily start/end hours; 15-minute increments, 06:00–21:00 and a minimum 30-minute interval are enforced, with no overnight interpretation. This default replaces a hard-coded illustrative 09:00–17:00 assumption across the PRIVATE zone triage, end-inclusive proposed reminder status, bounded rescheduling preview and exact revalidation. Changing any declared recipient window invalidates pending cross-zone proposals before apply. The selected-only PRIVATE CSV and scriptless HTML include the HUMAN-declared, explicitly unverified window; neither the requested zone nor the hours authenticate a person, their availability, consent or calendar delivery. This additional local control is not part of the original source-bound saved plan; re-enter it when reopening a session.

## PRIVATE HUMAN recipient-zone group workload and navigation

The alternate-zone planner also contains a new **source-local, 32-group-per-page workload desk**. It counts originally proposed HUMAN appointments per exact unverified source group and categorises each by recipient-local declared availability: within, outside daily hours, outside selected weekdays, unavailable local date, or recipient timezone clock change. The table includes a per-group **Focus group** button that filters the original-ordinal alternate-zone list and the PRIVATE converted-schedule export **exactly** to the selected HUMAN label. The existing status and text filters apply as additional restrictions. Clear exact focus to return to all groups. Neither the focus nor a group label authenticates a recipient, accepts an appointment or authorizes an assessment.

Invalid/duplicate recipient-blackout entries, malformed IANA zones, missing/invalid manual window fields or changed browser timezone now **clear and disable all prior recipient-zone rows, proposal actions and group-count preview** instead of leaving a stale private action table. Existing original HUMAN plans remain unchanged. No QA/test suite was created or run as part of this product work.

## Recipient-local unavailable dates and clock-change hold

The recipient zone can now declare **up to 60 exact local unavailable dates**, entered as comma-, semicolon- or whitespace-separated `YYYY-MM-DD` entries. Entries must be unique, valid calendar dates in 2000–2099. The unverified blackout policy applies to the **recipient-local date of BOTH the start and end of each proposed reminder**, even where the source and recipient use different calendar days. The local agenda displays these as **recipient unavailable local date**, supports an explicit filter, and never proposes or applies those times in the 12-ordinal common-hours planner. An invalid, duplicate or over-limit date list HOLDs the recipient desk and disables exports; original HUMAN scheduling remains untouched.

A separate status flags **recipient time-zone clock changes during the original HUMAN appointment duration**, using the browser's IANA UTC-offset information at start and end. Such slots are never silently treated as normal recipient availability, even where no local source-zone clock change occurs. They are filterable for explicit HUMAN review. This is browser-only timezone interpretation, not verified recipient timekeeping or calendar acceptance.

The exact HUMAN-declared date list is included in the source-bound unencrypted recipient preference CSV, the selected-only PRIVATE proposal CSV and scriptless review HTML. The converted-schedule CSV includes the date-list policy and per-event status. The original `human-followup.csv`, security findings and consent/grant decisions remain unchanged.

## PRIVATE source-bound recipient preference save/reopen

A new opt-in **Save PRIVATE source-bound recipient window (.csv)** stores exactly one bounded HUMAN-declared recipient IANA timezone, day policy, and start/end window with the **unsigned exact original worksheet SHA-256, opaque private calendar-series ID, and original local timezone**. Its three authority/verification/consent fields must be literal `false`. It is **separate** from the encrypted original `.luhw` and `.luhv` plan artifacts; the recipient's identity/real availability has not been independently authenticated.

The recipient preference CSV now uses an 11-column schema with its canonical semicolon-separated, sorted recipient unavailable date list. Strict legacy **10-column** source-bound preference files remain readable as an empty unavailable-date policy. No silent conversion into signed permission or authenticated recipient availability takes place.

To reopen, first import the same exact source HUMAN worksheet and its saved v2 plan (so the original SHA, private series and local source timezone match), then select **Restore PRIVATE recipient window (.csv)**. Only the exact two-row canonical header/schema under a 4 KiB bound is admitted; malformed, mismatched, BOM-prefixed, duplicate, oversized, unsupported timezone/hour/day or authority-claiming imports fail without changing the existing workroom or the recipient settings. The actual original HUMAN schedule, declared source-group rules and external calendars remain untouched. On a different source or calendar series, old manually declared recipient settings automatically reset rather than leaking across sources.

Recipient preference changes trigger an unsaved-local-workroom navigation warning until their private CSV is exported or a matching private preference file is reloaded. Keep this **cleartext** CSV private; unlike the encrypted workroom it is not password-protected. The original source-bound plan must still be saved separately to retain private event identities.

## Source-switch and workroom-reset privacy

When a different original HUMAN worksheet or calendar-series identity is imported, the recipient zone desk now **fully clears its previous source-derived rows, tentative change previews, exported/handoff button states, unsaved preference state, and pending preview actions** before the new source is rendered. This also happens when **Discard workroom** is confirmed; the recipient desk starts hidden and is only available after a HUMAN worksheet is opened. A previous source's private schedule data is not retained visibly after a source swap or reset. The reset confirmation includes unsaved recipient availability preferences. This is only browser-memory visibility hygiene, not a guarantee of OS/browser memory erasure or external data deletion.

## Calendar revision sequence for manual re-import

All three ICS output paths (complete plan, selected group, and changed/cancelled
events) now emit the same stable event UID per saved calendar series and
original ordinal plus a numeric SEQUENCE for each export batch. SEQUENCE uses
the local clock's epoch seconds and advances within the active browser session,
so later reschedule/cancellation exports normally supersede the earlier
tentative event instead of repeating the old constant sequence. Keep the
private v2 plan and import updates manually; there is no calendar API or sync.
Clock changes across devices/sessions are not authenticated chronology, and
calendar clients may still interpret imports differently. This remains a
local HUMAN planning aid, not evidence of a completed appointment, consent or
remediation.


## Latest-intent workspace replacement

Original worksheet import, plan-only CSV restore, encrypted plan restore and complete encrypted workroom restore share a local latest-intent generation. Selecting a newer replacement or confirming Reset invalidates earlier pending file reads/decryptions. A stale completion cannot replace a newer workspace, overwrite its status, clear its file input or erase the newer operation's password fields. The original worksheet bytes are zeroed on superseded/cancelled/successful paths after the admitted copy is made. The complete current workspace is committed only after the selected file is fully admitted and the existing source/fingerprint checks pass. This is a local race guard, not source authentication or permission; no network, browser persistence, actual calendar write, assessment execution or authorization is introduced.
