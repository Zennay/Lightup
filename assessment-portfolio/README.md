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
**Print visible PRIVATE queue** opens the browser's print dialog and excludes
hidden roles/rows and the control panel; printing may still retain sensitive
local planning metadata. Neither action changes original source documents,
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

## Interpretation and safety

- Input agenda exports are untrusted claims. Strict schema admission is not source authentication, reviewer authentication, customer identity, consent or security validation.
- `--as-of` is one operator-selected reference day for display. A past proposed date is a human discussion prompt, not a legal deadline, finding age, authorization expiry or proof of missed work.
- Source slot and agenda slot numbers are local ordinals only; they do not prove chronology.
- A missing source, absent flag or changed status is never interpreted as a verified fix.
- Planning flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, and `release_allowed=false`.
- No network, model, target, scanner, grant, active assessment, remediation, retest or release operation is performed.

This feature remains **DRAFT/HOLD** until the existing parent workbench and this exact child head receive all required CI, source-owner, independent security/privacy review and authorization gates. No QA/regression suites are added by this change.

The private routing CSV is sorted first by fixed neutral role, then proposed-date bucket, planned date and local ordinals. Every text field comes from an exact schema-admitted fixed vocabulary or generic question; role labels are suggestions, not verified people or assignments. Imported source dates are planning claims, not actual deadlines. No client IDs, target URLs, filenames, hashes or HUMAN notes are included.
