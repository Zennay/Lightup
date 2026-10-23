# LightUp · Cross-agenda human coordination portfolio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Issue #1629, implemented as new-only `assessment-portfolio/` files on a child of the exact original workbench commit `880d59e0a996005dce174516358ca04a48d4633d`. It does not replace or edit the original `assessment-archive/agenda.py`.

## Product behavior

Combine **2–12 already-created original private agenda JSON exports** from the unchanged `assessment-archive/agenda.py` against one explicit human planning reference day. The portfolio groups follow-up rows by neutral role and proposed-date bucket, includes a role-by-date workload matrix, preserves separate agenda/source slot ordinals, and never merges original source identifiers or bytes.

The output bundle contains four separate, no-overwrite artifacts in an existing directory owned by the current user with mode `0700`:

- `assessment-portfolio-private.html` — static, scriptless, CSP-pinned, printable private workroom. Shows only agenda and source slot ordinals, fixed source kind, human stage, neutral role, proposed review date, date bucket, and canonical generic question.
- `assessment-portfolio-private-routing.csv` — sorted PRIVATE per-item human coordination list for local spreadsheet/calendar preparation: admitted agenda/source ordinals, fixed source kind/stage/role, proposed date bucket and canonical generic human question. It contains no original source identifiers or bytes. It is **not an anonymous export** and must remain private.
- `assessment-portfolio-anonymous.json` — aggregate counts only.
- `assessment-portfolio-anonymous.csv` — aggregate counts only.

All four files are created with mode `0600`. The private HTML does not embed source bytes, source paths, filenames, hashes, targets, client identities or HUMAN commentary. Only the `assessment-portfolio-anonymous.json` and `assessment-portfolio-anonymous.csv` contain aggregate counts without row-level or per-agenda data. The private routing CSV is intentionally row-level, designed solely for local operator follow-up and must not be mistaken for anonymous data.

## Use

Use a local Python 3.11+ environment with the standard library only. Agenda input files must be owner-owned regular files with mode `0600`, no symlink/hard-link alias, and at most 128 KiB each. Duplicate agenda bytes, duplicate JSON keys, unknown fields, inconsistent count maps, mismatched date buckets, unknown stage/role/source-kind values, changed inputs and any true authorization/consent/dispatch/release flag fail the entire batch before outputs are published.

### Read-only preview (no output directory)

Use `--preview-only` to admit the same original agenda files, apply the selected focus filters and validate any selected HUMAN returns, but **never open/create an output directory or write files**. It prints only aggregate counts by neutral role, date bucket and HUMAN stage, plus the number/total byte size of the artifacts that would be rendered. If you explicitly select a declared capacity plan, the preview also shows only role/day group totals, over-limit group totals, excess-item totals and undated-item totals for the declared and optional alternate assumptions; these are hypothetical planning limits, not actual staffing. It does not print source paths, source hashes, original IDs, target labels or per-agenda rows.

```bash
python3 assessment-portfolio/portfolio.py \\
  --as-of 2026-10-23 \\
  --preview-only \\
  /private/agenda-room-a/agenda.json \\
  /private/agenda-room-b/agenda.json
```

All existing strict source admission and source re-admission still apply. A successful preview is only a local planning summary; it is not an authorization, approval, consent or evidence of completed remediation. For a private workroom or exact reopen, use the separate explicit output-directory workflow below.

Create a new, separate owner-only output directory; do not place it inside any original source room:

```bash
mkdir -m 700 /private/new-assessment-portfolio
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-21 \
  --output-dir /private/new-assessment-portfolio \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

The directory must already exist, be owned by the current user and have mode `0700`. Existing output filenames cause HOLD rather than overwrite. If bundle publication fails part-way, newly created files are removed. Input paths are opened component-by-component without following symlinks; inputs must remain stable during the read.

## Reopen and focused HUMAN workrooms

Reopen an existing, private four-file packet without modifying any input or
output. This reconstructs the original four canonical artifacts from the same
admitted source agenda bytes, the **same** `--as-of` day and any original
focus flags, and compares the complete output bytes with an exact inventory.
Extra files, missing files, non-0600 files, hard links, symlinks, different
content or changed original agenda bytes produce HOLD. Reopening cannot
authenticate the original HUMAN or client claims: it only proves these local
files match the currently re-admitted original input bytes.

```bash
python3 assessment-portfolio/portfolio.py \
  --verify-output-dir \
  --as-of 2026-10-21 \
  --output-dir /private/new-assessment-portfolio \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

For an operator who needs a smaller **PRIVATE** task desk, use any combination
of `--focus-role`, `--focus-stage` and `--focus-bucket`. All source
agendas are still admitted in full; only the resulting HUMAN follow-up rows
and their stage/role/date count summaries are filtered. No source detail or
HUMAN note is ever added. Use a **new empty owner-only 0700** output directory,
never the original full-portfolio directory.

```bash
mkdir -m 700 /private/reviewer-followup
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-21 \
  --focus-role reviewer \
  --focus-stage NEEDS_ORIGINAL_EVIDENCE \
  --focus-bucket PAST_PLANNED_DATE \
  --output-dir /private/reviewer-followup \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

The filtered four-file packet uses aggregate schema
`lightup.assessment_portfolio_aggregate.v2` with an explicit `view_selection`
in its counts-only JSON, plus explicit view-selection rows in its counts CSV, while the **unchanged unfiltered** export continues
to use v1. Every focused HTML view labels the exact selected role, stage and
reference-date bucket. A selection matching no HUMAN items yields a clearly
labelled empty private desk, **not** evidence that work is completed. Original
source status claims are retained for context and are never promoted to
verified approvals. Reopening the filtered packet requires the identical
selection flags and source ordering along with `--verify-output-dir`.

During creation the original agenda bytes are readmitted immediately before
private publication. A changed original source aborts rather than publishing
a stale derived packet. This is a local source-drift guard, **not** a trusted
signature, contemporaneous reviewer identity, grant, proof of consent or
permission to distribute the packet.

### Source-list mode for large PRIVATE agendas

Instead of repeating 2–12 private source filenames on the command line, create
a local **0600** UTF-8 text file with exactly one absolute original agenda path
per LF-terminated line, in the intended **manual** agenda order. All source
files still require their own mode-0600/no-symlink/no-hard-link admission; the
list does not grant authority or execute any assessment. Relative paths, blank
lines, duplicate paths, CRLF, embedded NUL, hidden Unicode control/bidi
marks, symlinks, oversized lists and changed list contents cause HOLD.

```bash
umask 077
cat > /private/agenda-selection.txt <<'EOF'
/private/agenda-room-a/agenda.json
/private/agenda-room-b/agenda.json
EOF
chmod 600 /private/agenda-selection.txt
mkdir -m 700 /private/selected-workroom
python3 assessment-portfolio/portfolio.py \
  --agendas-file /private/agenda-selection.txt \
  --as-of 2026-10-21 \
  --output-dir /private/selected-workroom
```

The `--agendas-file` input and positional source paths are **mutually
exclusive**. Creation and read-only `--verify-output-dir` accept the same
selection-list form, and the list's parent folder cannot contain output.
Operator-selected list order is never interpreted as authentic chronology.
The manifest is sensitive because it contains local private paths: it is
never written into the four derived portfolio artifacts.

## Offline interactive HUMAN explorer and tentative calendar

The original four-file workroom remains unchanged by default. You may
explicitly add either or both PRIVATE artifacts to a **new** mode-0700 workroom
with `--private-explorer` and `--private-calendar`. Never use these options
to overwrite an existing packet: all outputs use exclusive mode-0600 writes.

```bash
mkdir -m 700 /private/local-human-workroom
python3 assessment-portfolio/portfolio.py \
  --agendas-file /private/agenda-selection.txt \
  --as-of 2026-10-22 \
  --private-explorer \
  --private-calendar \
  --output-dir /private/local-human-workroom
```

**PRIVATE cross-agenda coordination views:** Both the original static PRIVATE
HTML and the optional interactive PRIVATE explorer now show a per-agenda HUMAN
workload matrix, with neutral-role and proposed date-bucket counts, plus direct
ordinal links to each agenda's first source item in the worklist. They also
show same-proposed-day/same-neutral-role *attention clusters* (two or more
rows) and links to each ordinal so one human can discuss competing proposals
without paging between source files. This is **not** proof of a genuine
individual schedule conflict, assignment, deadline, elapsed time,
remediation, missing source resolution or authorization. These per-agenda
details appear only in PRIVATE HTML, not the anonymous JSON/CSV.
A filtered workroom calculates both PRIVATE views using only the admitted
filtered subset and explains that absence of visible rows is not completion.

**Interactive PRIVATE explorer**:
`assessment-portfolio-private-explorer.html` opens without a web service and
enhances the existing role-grouped work tables with client-side filtering by
neutral role, non-authorizing HUMAN stage, proposed date category, and fixed
human-question/ordinal text. Visible-item totals update locally; clearing
filters restores the original admitted table. **Download visible rows (PRIVATE
CSV)** produces a separate local spreadsheet handoff containing *only currently
visible human-planning rows*, fixed admitted field values, and an explicit
REVIEW_ONLY authority column. Text is quoted and spreadsheet-formula-like
prefixes are neutralized. The downloaded CSV is explicitly **PRIVATE**,
not the anonymous aggregate and not an instruction to contact any recipient.
**Print visible PRIVATE queue** opens the browser's print dialog and prints
only the role sections/rows visible under the current local filters, together
with an explicit print-only filter-context summary and HOLD disclaimer.
The PRIVATE whole-portfolio summary, per-agenda workload and same-day cluster
matrices are deliberately **excluded from filtered print**, as they may carry
unfiltered planning details. Printing may still retain sensitive local
planning metadata. Neither action changes original source documents,
rounds or the server, and no file is uploaded. JavaScript and additional
print styles are each exact SHA-256 CSP-pinned; there is no network, external
asset, browser persistence, automatic dispatch, scanner or permission
creation. Browser downloads and print require explicit clicks. The original
`assessment-portfolio-private.html` remains **scriptless** and still comes
in the packet.

**Calendar of PRIVATE human proposals**:
`assessment-portfolio-private-proposals.ics` contains only previously
entered proposed dates and fixed-vocabulary ordinal/role/stage labels.
Undated proposals are **not given invented deadlines** or calendar entries.
Each dated entry is an all-day, tentative, transparent (nonblocking)
HUMAN discussion reminder. There are no attendees, meeting invites,
alarms, organizer fields, target addresses, actual client names, case IDs,
HUMAN notes, original paths or scanner instructions. The calendar's
deterministic DTSTAMP uses the explicit `--as-of` reference day at midnight
UTC **only as a technical reproducibility marker**: it does not prove
when any real meeting, original assessment or human decision occurred.

The CLI never connects to a calendar or synchronizes the file. **Importing
a private .ics into a third-party calendar may send planning metadata to
that provider**. Review recipients, privacy and synchronization settings
outside this tool before choosing to import it. It does not create consent,
a real deadline, an assignment, a work order, or permission to scan.

With neither option there are exactly four output files; selecting one
adds exactly one, selecting both adds two. All have the same owner-only
permissions, exclusive publication, full canonical read-only reopen and
original-source-drift safeguards. To reopen exactly the same optional
packet, repeat its original source selection/order, reference day, optional
focus flags, `--private-explorer`, `--private-calendar`, and add
`--verify-output-dir`. Missing, extra, changed or owner-unsafe outputs
cause HOLD; no regeneration silently overwrites them. Every individual
artifact is bounded to 1 MiB. Focused workrooms generate explorer/calendar
rows from **only the selected HUMAN rows**, and the counts-only exports
still identify the chosen explicit view filter.

## A single PRIVATE local HUMAN start screen

Whenever the operator explicitly requests a `--private-human-workbook` or
supplies `--human-responses`, the packet also includes
`assessment-portfolio-private-HUMAN-home.html`, a **scriptless,
source-reconstructed, CSP-SHA256-pinned local navigation screen**. It links
only the exact original and optional PRIVATE packet artifacts that were
actually created: original agenda view, routing CSV, counts-only source
summaries, interactive exploration, tentative calendar, HUMAN worksheet,
later PRIVATE HUMAN status-by-role return, and optionally the two-round
HUMAN change desk. The links are restricted to a fixed in-repository
filename vocabulary, relative to the existing owner-private 0700 folder.

Open this PRIVATE home directly from disk. It never calls a service, creates
a grant, forwards files, dispatches a review or claims production consent.
Original client inputs remain outside this directory. There are no
authenticated recipients or real deadlines in this menu. Packet publication
and read-only `--verify-output-dir` include the home page's exact bytes,
so an unexpected/missing private navigation target fails the original
canonical inventory gate. Original four-file-only portfolio runs still
create precisely the same four files as before; the home is **opt-in
through the HUMAN workflow**, not an unsolicited artifact.

## Complete PRIVATE HUMAN worksheet round trip (opt-in)

The original cross-agenda planning report is intentionally **not** an
assessment, consent gate, signed approval or authoritatively assigned task.
To turn previously admitted private agenda items into a human-only discussion
follow-up **without changing the original files**, generate an extra
`assessment-portfolio-human-workbook.html` from the same canonical source
agendas using the explicit `--private-human-workbook` flag:

```bash
mkdir -m 700 /private/portfolio-human-original
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --agendas-file /private/agenda-selection.txt \
  --private-human-workbook \
  --output-dir /private/portfolio-human-original
```

Open that PRIVATE workbook locally. Its CSP SHA-256-pinned JavaScript runs
entirely inside the browser, requires **no server or network**, and provides
one editable human-only discussion status, a suggested neutral role and a
single-line PRIVATE HUMAN note (maximum 160 characters) per source ordinal.
The statuses are only `PENDING_HUMAN`, `DISCUSSING`,
`AWAITING_ORIGINAL`, and `DOCUMENTED_DISCUSSION`; there is intentionally
**no approved, resolved, verified, consent, granted or dispatched state**.
The fixed original stage/role, date and source ordinals are visible but
**not editable**. The worksheet now includes local filters by current HUMAN
discussion state and proposed role, plus a fixed-field search. Select individual
rows or select all rows visible under the current filter; then preview the exact
number of selected rows and stage/role fields that would change. Applying a
batch requires explicit confirmation and changes only selected visible HUMAN
fields. Original agenda fields and private notes are untouched. One-step Undo
restores the previous HUMAN stage/role values only until another individual
HUMAN edit or a source-bound worksheet restore invalidates it. Filtering clears
the selection so hidden rows cannot be accidentally included. These controls
are local planning conveniences, not evidence, assignment, approval or
authorization. The screen shows unsaved local changes and an explicit
**Download private HUMAN response JSON** action. Closing the tab discards
unsaved work; there is no cookie, localStorage, external asset or telemetry.

**Resume local HUMAN work** by selecting a previously downloaded private
worksheet JSON in the same original HTML. The browser admits the whole
document atomically against the original row binding, strict fixed source
fields and allowed HUMAN values; an invalid imported file leaves the
currently edited screen unchanged. The local browser is only an editor and
does **not** authenticate the author or replace the original native input
gate. Never include passwords, target credentials, private customer data or
vulnerability reports in its notes.

To publish a separate follow-up, save the downloaded browser JSON as a
**single-hard-link, current-user-owned, exact mode-0600 private source file**
in a secure location **outside** the destination directory. Most browsers
do not guarantee mode 0600 on downloads, so review local file handling and
secure its permissions before native admission:

```bash
chmod 600 /private/human-input/lightup-PRIVATE-HUMAN-worksheet.json
mkdir -m 700 /private/human-return-new
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --agendas-file /private/agenda-selection.txt \
  --human-responses /private/human-input/lightup-PRIVATE-HUMAN-worksheet.json \
  --output-dir /private/human-return-new
```

This produces the unchanged original four packet files **plus** an
owner-private mode-0600 scriptless `assessment-portfolio-private-HUMAN-return.html`
and `assessment-portfolio-private-HUMAN-return.csv`, plus a separate\nmode-0600 `assessment-portfolio-private-HUMAN-summary.json`. The HUMAN return
contains only source ordinals, fixed original stages/proposed dates and the
locally entered HUMAN-only proposed role/status/note. Original source
paths, target details, raw agenda IDs and hashes never enter either return.
The additional PRIVATE summary gives a compact HUMAN-status × proposed-role
workload matrix, aggregate proposed role/status counts and a count of local
HUMAN notes. The scriptless PRIVATE return HTML shows the same grouped
matrix before the detailed rows. Even small-cell counts may reveal local
planning context, so **neither PRIVATE rollup is an anonymous export**.
It never claims a completed remediation, verified finding, authenticated
reviewer or clearance; approval/consent/dispatch flags remain false.

PRIVATE HUMAN notes can themselves be sensitive and are never added to the
anonymous JSON/CSV. The native module strictly rejects malformed JSON,
duplicate keys, unknown fields, modified fixed source rows, incompatible
row-reference digests, unsafe note/control text, unknown roles/statuses,
unexpected authority flags and duplicate/changed/unsafe input files.
Every source is re-admitted immediately before publication. No original
agenda is changed or marked completed.

The previously used command plus **identical** source order, reference
day, optional `--focus-*` selection and exact same flags with
`--verify-output-dir` reopens the complete packet **without writing**.
Note that `--private-human-workbook` is also independently optional during
this return: include it on the final command only if the follow-up packet
should also contain a brand-new blank worksheet; otherwise it contains just
the canonical four original outputs and three private HUMAN returns.
Do not place the HUMAN response source in its destination room. The
HUMAN return is **planning evidence only**: no real sign-off, source
identity verification, consent, action-time revocation, assessment execution,
issue resolution or release approval is conferred by these files.

## Compare two source-bound PRIVATE HUMAN discussion rounds

The same CLI can now compare **two independently saved private HUMAN responses**
against the **same original 2–12 agendas**, the same manually selected
reference day, the same source order and any identical `--focus-*` filters.
The earlier/later ordering is strictly **provided by the human operator**;
neither a source timestamp nor a file name is treated as authentic chronology.
Both HUMAN response files must be separately owner-owned mode 0600, regular,
single-linked, unchanged on bounded re-read, and kept outside the new
destination room.

```bash
mkdir -m 700 /private/human-delta-room
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --agendas-file /private/agenda-selection.txt \
  --previous-human-responses /private/human-input/round-earlier.json \
  --human-responses /private/human-input/round-current.json \
  --output-dir /private/human-delta-room
```

The output includes all canonical original four portfolio outputs, the
three PRIVATE HUMAN return artifacts for the later-supplied round, its
scriptless PRIVATE HUMAN navigation home, and two additional owner-private files:
`assessment-portfolio-private-HUMAN-delta.html` and
`assessment-portfolio-private-HUMAN-delta.json`. They present only
**source ordinals**, changes in HUMAN-only status, changes in suggested role,
and whether note bytes differed. Neither delta contains the earlier or later
note text, any original raw source identifiers or target data. The scriptless
HTML highlights only changed source ordinals; the private JSON also includes
bounded aggregate stage-transition counts. These are **PRIVATE**, not
anonymous handoffs; small ordinal sets may reveal planning context.

The tool re-admits both source-bound HUMAN JSON documents against all original
canonical fixed agenda rows before publication and re-reads both before the
final no-overwrite output. It rejects different source selection/order or
reference day, modified original fields, extra columns, unknown statuses,
unsafe notes, contradictory authority flags or drifted original sources.
Use `--verify-output-dir` with **the identical command, original input,
flags and file paths** to reopen the complete output read-only.

A changed HUMAN status, suggested reviewer role, documented discussion or
changed note **never proves that a finding was fixed, that a request is
approved, that a person consented, or that an assessment may run**. This
is merely HUMAN planning comparison in an offline lab draft. No review
result, consent, grant, scan, dispatch, network action or release is made.

## Multi-round PRIVATE HUMAN timeline (2–8 operator-supplied rounds)

The opt-in `--human-history-file` workflow combines **2–8 separately saved original-bound
PRIVATE HUMAN worksheet responses** against the same fully admitted original agenda
selection, source ordering, reference day and any identical focus filters. Prefer the
private path-list form so the individual response paths are not repeated in the shell
command or process arguments. The UTF-8 list must be owner-owned, mode `0600`, single
linked, LF-terminated, bounded, and contain exactly one normalized absolute path per
line in the explicitly chosen order. The list itself is sensitive and must stay outside
the new output room.

```bash
umask 077
cat > /private/human-history-selection.txt <<'EOF'
/private/human-input/round-earlier.json
/private/human-input/round-middle.json
/private/human-input/round-later.json
EOF
chmod 600 /private/human-history-selection.txt
mkdir -m 700 /private/human-timeline-room
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --agendas-file /private/agenda-selection.txt \
  --human-history-file /private/human-history-selection.txt \
  --private-home \
  --output-dir /private/human-timeline-room
```

Every response must independently pass the original-row binding, fixed HUMAN status/role
vocabulary, owner-only regular-file and bounded stable-read admission. Repeated paths,
changed source rows, incompatible reference days, unsafe inputs or output inside any
input room cause HOLD before publication. Alternatively, repeat
`--human-history /absolute/private/response.json` once per round; this direct form is
less private because response paths may appear in shell history and process listings.

The packet retains the canonical four portfolio outputs and adds three owner-private
mode-`0600` artifacts: `assessment-portfolio-private-HUMAN-timeline.html` (scriptless
local side-by-side history), `assessment-portfolio-private-HUMAN-timeline.json`
(structured ordinal-level transitions and per-round summaries), and
`assessment-portfolio-private-HUMAN-timeline.csv` (one row per original ordinal and
operator-supplied round). A scriptless private home links the exact files created.
The timeline reports status/role changes and whether a private note changed, but it
never copies note contents, input paths, filenames, hashes, targets or client
identifiers into the timeline. The CSV and timeline are **PRIVATE, not anonymous**;
ordinals and small-cell counts can reveal local planning context.

Round 1, Round 2, and so on reflect **only the explicit order chosen by the operator**.
The feature does not infer or authenticate chronology from timestamps, filenames or
notes. It cannot establish reviewer identity, source authenticity, consent, remediation,
task completion, approval, a grant or permission to scan. Original agenda and HUMAN
response bytes are re-admitted before publication. Existing output names are never
overwritten; read-only `--verify-output-dir` must repeat the same original sources and
order, reference day, focus flags, history list/source paths and optional output flags.

The history workflow is mutually exclusive with pairwise `--human-responses` /
`--previous-human-responses` delta inputs. This remains offline **INCUBATE M3/M7
PLAN/LAB ONLY / DRAFT-HOLD**; all original CI, source-owner, independent
security/privacy review, #177/#182/#829 and separate current consent/action-time
revocation/HUMAN GO gates remain binding.

## Interpretation and safety

- Input agenda exports are untrusted claims. Strict schema admission is not source authentication, reviewer authentication, customer identity, consent or security validation.
- `--as-of` is one operator-selected reference day for display. A past proposed date is a human discussion prompt, not a legal deadline, finding age, authorization expiry or proof of missed work.
- Source slot and agenda slot numbers are local ordinals only; they do not prove chronology.
- A missing source, absent flag or changed status is never interpreted as a verified fix.
- Planning flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, and `release_allowed=false`.
- No network, model, target, scanner, grant, active assessment, remediation, retest or release operation is performed.

This feature remains **DRAFT/HOLD** until the existing parent workbench and this exact child head receive all required CI, source-owner, independent security/privacy review and authorization gates. No QA/regression suites are added by this change.

The private routing CSV is sorted first by fixed neutral role, then proposed-date bucket, planned date and local ordinals. Every text field comes from an exact schema-admitted fixed vocabulary or generic question; role labels are suggestions, not verified people or assignments. Imported source dates are planning claims, not actual deadlines. No client IDs, target URLs, filenames, hashes or HUMAN notes are included.


## Source-scoped PRIVATE calendar and role-day overview (22 October 2026)

The opt-in original `--private-calendar` now computes local calendar UIDs from
canonical re-admitted **original agenda contents** plus the original source slot,
the HUMAN role/stage, date and explicit planning reference day. Previously two
distinct local portfolio sources with the same positional ordinals, role and
date could generate colliding calendar UIDs even though their original agendas
were different. Stable source-scoped UIDs avoid that accidental cross-agenda
replacement. They are **not** signatures, grants, trusted source IDs, or proof
that a meeting happened. Changing the original content may intentionally
create a new UID; operators should review stale copies in calendar apps.

For a compact manual staffing overview, add `--private-calendar-clusters`.
It creates **one tentative, transparent all-day proposal per suggested neutral
role and proposed review date**, containing only item counts, agenda-slot
counts and non-authorizing generic text. It never sends invitations, writes to
a calendar service, schedules alarms, authenticates the proposed role, books
a meeting, proves a finding, or treats missing entries as completed work.
Unscheduled HUMAN rows are kept in the original PRIVATE workroom and omitted
from calendars, never assigned invented dates.

```bash
mkdir -m 700 /private/new-human-calendar-room
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --private-explorer \
  --private-calendar \
  --private-calendar-clusters \
  --output-dir /private/new-human-calendar-room \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

Two separate opt-in local files are generated when both flags are selected:
`assessment-portfolio-private-proposals.ics` (per original HUMAN item)
and `assessment-portfolio-private-role-day.ics` (per date + neutral role).
Both are original-source-derived, remain owner-private mode 0600 in the same
0700 private room, and are checked byte-for-byte by the **same** command with
`--verify-output-dir`. They are distinct views of the *same* HUMAN proposals:
**do not import both into the same active calendar** unless intentional, or
duplicate visual proposals may appear. The cluster view is not a replacement
for source-by-source review and contains no actual calendar commitments.
No networking, target contact, browser persistence, grants or active assessment.
Original CI, independent source/privacy/security review, true separate current
client/operator consent with action-time revocation and explicit HUMAN GO
remain mandatory before any authorized live functionality. This draft stays
INCUBATE M3/M7 PLAN/LAB ONLY and MUST NOT be deployed.


## Printable PRIVATE role/day brief

Use `--private-day-brief` to include
`assessment-portfolio-private-day-brief.html`, a small standalone,
**scriptless** print/read companion to the canonical full PRIVATE
workroom. It groups **all** admitted selected rows, including single-item
role/date groups and rows without an original proposed date. Each entry
contains only a neutral stage/kind, canonical generic HUMAN question
and a local ordinal link (Axx/Sxx) back to
`assessment-portfolio-private.html` in the same private folder.

```bash
mkdir -m 700 /private/assessment-role-day-brief
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --private-day-brief \
  --private-calendar-clusters \
  --output-dir /private/assessment-role-day-brief \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

The browser needs no scripts or resources outside that private output
directory; output remains mode 0600 and is included in the strict exact-byte
`--verify-output-dir` re-open. `--focus-role`, `--focus-stage` and
`--focus-bucket` still limit the resulting private brief; an empty match
is explicitly not a completed review. This separate view does **not**
authenticate the person associated with a role, prove that the proposed
date is booked, authorize a scan or amend any original source.


## 22 October 2026 — exact-day / source-kind HUMAN queue and PRIVATE spreadsheet

The native portfolio now supports `--focus-day YYYY-MM-DD` (the actual
originally proposed human review date, **not** an invented calendar day) and
`--focus-kind KIND` (one of the six original fixed
`source_kind` categories). Both may be combined with the existing
`--focus-role`, `--focus-stage` and `--focus-bucket` to produce a
small, private exact selection. Source agenda files are still admitted
**completely** before any row filtering. The original *unfiltered* v1 and
three-dimension focused-v2 packet schemas remain unchanged; the extra
`view_selection` keys are included in v2 **only if** one of the new
dimensions is actually requested.

Add `--private-role-day-csv` to generate
`assessment-portfolio-private-role-day.csv`: a source-minimal owner-only
spreadsheet of each original proposed day × neutral role, the number of HUMAN
items and original agendas, and PRIVATE source-slot ordinals. Unlike
counts-only public aggregates, this opt-in row grouping is **PRIVATE**,
even without source names, because dates and small counts reveal work context.
Unscheduled items are retained under a blank day; empty selections create a
header-only spreadsheet (not a completed-work conclusion). Its fields
are fixed original enums/dates, integers and ordinals, with explicit
`REVIEW_ONLY` labels. No identifiers, targets, raw source paths, sensitive
HUMAN notes, URLs or network operations enter the CSV.

```bash
mkdir -m 700 /private/new-exact-day-planning
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --focus-day 2026-10-30 \
  --focus-kind completed_lab_case_claim \
  --private-day-brief \
  --private-role-day-csv \
  --private-human-workbook \
  --private-calendar-clusters \
  --output-dir /private/new-exact-day-planning \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

This combination creates the original four artifacts plus a PRIVATE
day-brief HTML, grouped role/day CSV, role/day tentative ICS, local HUMAN
worksheet, and a standalone scriptless HUMAN start page that links to
**all** of those exact local artifacts. The original private output
directory must already exist with mode 0700; individual outputs use exclusive
0600 publication with complete exact-byte reopening. Repeat **all** options,
original source order and the reference day with `--verify-output-dir`
to readmit the same bundle without changes.

This product proposes HUMAN discussion only. It does not book meetings,
authenticate identities, verify findings, create consent, authorize live
targets, grant privileges, dispatch work or schedule scanners. Client/operator
consent, action-time revocation, independent privacy/security/source-owner
review, original #177/#182/#829 gates, hosted and permanently named VPS CI and
explicit HUMAN GO remain independent prerequisites for any future release.


### Optional PRIVATE start screen even without a HUMAN worksheet

The native `--private-home` flag now explicitly publishes
`assessment-portfolio-private-HUMAN-home.html` for **any** selected
portfolio packet, even when the browser HUMAN editor was not requested.
It links only the precisely generated original/private artifacts using
the fixed filename allowlist; it neither imports source files nor
performs any requests, target work, share or dispatch. The previously
supported automatic start page with `--private-human-workbook` or
`--human-responses` is unchanged. With no `--private-home` and no
HUMAN workflow selected, the original four-file output remains
unchanged.

```bash
mkdir -m 700 /private/portfolio-briefing-home
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --private-home \
  --private-day-brief \
  --private-role-day-csv \
  --output-dir /private/portfolio-briefing-home \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

Read-only reopening must repeat `--private-home` and the complete exact
selection. This is local PRIVATE navigation, not independently authenticated
source provenance, authorized disclosure or a production dashboard.


### Bounded original HUMAN date window (91 days maximum)

For a weekly/monthly operator-planning packet, select inclusive
`--focus-from YYYY-MM-DD --focus-through YYYY-MM-DD`. Both bounds are
required; reversed windows, an interval over 91 calendar days,
out-of-policy dates and mixing the window with `--focus-day` produce
HOLD **before any private output is created**. These dates are filters
on original human-*proposed* review dates, never inserted into the
source agenda. Rows without an original proposal stay in the complete
source admission but are excluded from this deliberately dated view.
An empty result means no matching HUMAN proposals, NOT that work has
been completed or authorized.

```bash
mkdir -m 700 /private/next-week-human-work
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --focus-from 2026-10-26 \
  --focus-through 2026-11-01 \
  --private-home \
  --private-day-brief \
  --private-role-day-csv \
  --private-calendar-clusters \
  --output-dir /private/next-week-human-work \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

The focused v2 aggregate adds explicit `proposed_date_from` and
`proposed_date_through` selection markers only when the range is
requested. The original unfiltered v1 and old focused v2 markers
remain unchanged. Repeat all focus flags to reopen the same private
packet strictly with `--verify-output-dir`. Planning dates are
unauthenticated HUMAN claims and must never be represented as
confirmed deadlines, calendar bookings, real findings or consent.


## 22 October 2026 — PRIVATE HUMAN capacity assumptions (offline)

`--private-capacity-plan` publishes two additional **source-minimal, owner-only**
artifacts from already admitted original HUMAN follow-up agenda rows. This
is not staffing data, a scheduling service or authorization to do assessments.

An operator explicitly supplies `--daily-capacity N` for the *hypothetical*
maximum number of HUMAN discussion items a **neutral role** might handle
on one *originally proposed review day*. One may override selected fixed roles
with `--role-capacity ROLE=N`. All numbers must be integers **1–128**;
unknown or repeated roles, missing/default-only numbers, or capacity options
without `--private-capacity-plan` cause HOLD. No capacity is inferred from
client data, employee identity, calendar bookings or source files.

```bash
mkdir -m 700 /private/assessment-capacity-room
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --focus-from 2026-10-26 \
  --focus-through 2026-11-01 \
  --private-capacity-plan \
  --daily-capacity 4 \
  --role-capacity reviewer=3 \
  --role-capacity privacy=2 \
  --private-home \
  --private-day-brief \
  --private-role-day-csv \
  --output-dir /private/assessment-capacity-room \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

The resulting packet adds:

- `assessment-portfolio-private-capacity.html` — **scriptless** CSP-pinned
  role × originally proposed date overview, with source ordinal links to the
  original PRIVATE workroom, explicit operator assumptions, and
  `max(0, proposed HUMAN items - operator's declared limit)` displayed as
  a hypothetical **excess**, not as a real schedule collision or shortage.
- `assessment-portfolio-private-capacity.csv` — **PRIVATE** spreadsheet
  grouping dates, neutral roles, declared item counts, proposed excess and
  original source ordinals. It is not an anonymous export and is never
  distributed automatically.

Rows with no original proposed review day remain in an explicit
UNSCHEDULED section and CSV rows with blank date and no capacity/excess;
they are **not** silently assigned synthetic dates or treated as reviewed.
A filter matching no original HUMAN rows produces an empty clearly
non-authorizing capacity desk, not a completed-work statement. Source
identities, targets, actual HUMAN notes and original private file paths are
excluded; ordinal links remain sensitive planning metadata. Original
private inputs and authentic provenance/consent never change.

These two new outputs participate in the **same** bounded 1-MiB-per-file,
owner-owned directory mode-0700, exclusive mode-0600 local publisher as
the original canonical packet, and the existing exact-byte
`--verify-output-dir` read-only reopen mechanism. Reopen with **identical
source order, reference day, filters, proposed capacities and output flags**;
changed assumptions intentionally produce a mismatch. When
`--private-home` or a HUMAN worksheet is selected, the home links the exact
two private capacity outputs through its fixed asset allowlist.

This is an **operator-provided hypothetical limit** for discussing original
HUMAN proposals, never an observed reviewer availability, an authenticated
assignment, a security risk conclusion, approved scope, proof of consent,
HUMAN GO, scan or launch. The original owner, privacy/security and hosted /
permanently registered VPS CI gates and #177/#182/#829 remain binding.


## Alternative declared-capacity scenario (PRIVATE HUMAN comparison)

The capacity desk can now compare **two separately and explicitly entered**
neutral-role/day workload assumptions over the **same** original PRIVATE
agenda selection. Pass `--alternate-daily-capacity N` (1–128 proposed
HUMAN discussion items/role/day), optionally followed by individual
`--alternate-role-capacity ROLE=N` overrides. Alternative overrides
without a second default or a second scenario without the
`--private-capacity-plan` base are rejected before any output.

```bash
mkdir -m 700 /private/role-day-scenario-review
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --focus-from 2026-10-26 \
  --focus-through 2026-11-01 \
  --private-home \
  --private-capacity-plan \
  --daily-capacity 3 \
  --role-capacity privacy=2 \
  --alternate-daily-capacity 5 \
  --alternate-role-capacity privacy=3 \
  --output-dir /private/role-day-scenario-review \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

Besides the original PRIVATE capacity overview and CSV, this creates:

- `assessment-portfolio-private-capacity-comparison.html` —
  printable, **scriptless CSP-hash-pinned** first-vs-alternative assumption
  table for each originally proposed date and neutral role, with original
  source-ordinal links and aggregate arithmetic difference.
- `assessment-portfolio-private-capacity-comparison.csv` —
  PRIVATE date/role/ordinal values, both manually entered limits, both
  counts above those limits and their mathematical difference. This is a
  human-only spreadsheet, **not** a counts-only anonymous export.

Source rows without original proposed dates remain excluded from both
daily counts and are displayed as undated totals; they are never assigned
invented deadlines. Neither scenario proves real reviewer availability,
assignments, authentic client consent, actual improvement, work completion,
a security finding or authority to run a scan. An apparently smaller
arithmetic excess is **not** independent operational validation.

Both alternative artifacts are present only with an explicit alternative
scenario, remain exclusive owner-private mode 0600 in the 0700 output
directory, and are included in the original byte-for-byte
`--verify-output-dir` reopen. Reopening requires **the exact same first
and alternative capacity flags**. The existing scriptless PRIVATE home
includes both files under fixed names and never posts to a service.
This draft remains INCUBATE M3/M7 · PLAN/LAB ONLY / DRAFT-HOLD until
original source-owner, security/privacy, hosted/named-runner CI,
#177/#182/#829, authenticated separate current client/operator consent,
revocation-at-action and explicit HUMAN GO requirements are satisfied.


## Interactive PRIVATE capacity scenario studio — browser-memory only

The optional `--private-capacity-studio` flag generates
`assessment-portfolio-private-capacity-studio.html` in the same
owner-only source-bound output packet. It requires
`--private-capacity-plan --daily-capacity N` and may start from the
optional alternative declared capacity. No browser editor is produced
without an explicit native original capacity admission.

```bash
mkdir -m 700 /private/human-capacity-studio-room
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-22 \
  --focus-from 2026-10-26 \
  --focus-through 2026-11-01 \
  --private-home \
  --private-capacity-plan \
  --daily-capacity 4 \
  --alternate-daily-capacity 6 \
  --private-capacity-studio \
  --output-dir /private/human-capacity-studio-room \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

Open the generated PRIVATE start page and then the capacity studio. It
contains only **strictly admitted original proposed dates, fixed role
labels, counts and local ordinal links**, not original filenames, client
identifiers, endpoints, private HUMAN notes or authorization claims.
Locally adjust the first and alternative hypothetical HUMAN items/day
for each fixed neutral role (integers 1–128). The browser recalculates
both arithmetic scenario totals immediately, presents original row
drilldowns, permits printing the PRIVATE screen and explicitly
downloading a bounded PRIVATE comparison CSV or structured PRIVATE JSON
handoff. The JSON includes the reference date, first/alternative role
limits, arithmetic summary, and date/role group counts with original
source-local ordinals. Undated rows remain null-dated and receive no
invented capacity. The JSON excludes source filenames, source hashes,
identities and HUMAN notes. Invalid entries make both downloads
unavailable rather than silently defaulting to a limit.
The original native PRIVATE baseline/comparison artifacts are **not**
overwritten by browser-memory edits. Reset restores exactly the initial
native-assumed values; closing the page discards edits.

This studio is a SHA-256 CSP-pinned **single local HTML file**: no
external assets, storage, cookies, network, model, target calls, scan,
grant, real calendar booking, authenticated recipient, consent or
dispatch. Browser CSV downloads/prints may retain PRIVATE derived
planning metadata and must not be shared without independent review.
A smaller hypothetical excess is not a staffing conclusion or
evidence of completed remediation. For persistent original-source-
reproducible assumption changes, create a **new** separate 0700
PRIVATE packet with the desired original native CLI flags. The
immutable native packet can be reopened with the same options and
`--verify-output-dir`, but edits made inside the browser studio are
memory-only and are **not** represented as original native evidence.


### PRIVATE studio: no stale scenario export

The memory-only browser studio also preserves **original undated HUMAN
proposal ordinals** as a separate local section with original workroom
links. Those rows appear in any explicitly downloaded PRIVATE scenario
CSV with empty proposed date and empty capacity/arithmetic columns. They
are not silently omitted and do not consume invented day limits. If a
human enters an invalid scenario limit, the studio clears its last
calculated table and summary and disables both print and export until
**every** fixed-role input is valid again; it never silently saves or
exports a stale scenario, and both CSV/JSON exports remain disabled. The
native source-bound 0600 artifacts are
unchanged by local edits.
