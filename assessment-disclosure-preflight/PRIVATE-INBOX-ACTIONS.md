# LightUp PRIVATE HUMAN inbox actions

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This companion is a
local manual task sheet for a *previously created* source-free PRIVATE
multi-room inbox board. It does **not** execute an assessment, authenticate
a real customer/reviewer, verify findings, assign teams, grant consent,
release reports, scan targets or contact a network.

## Workflow

## Recommended: create the complete board and bound HUMAN template together

The native `private_inbox_workroom.py` publishes the source-free board and
its exact-byte-SHA-bound HUMAN template in a single exclusive operation:

~~~sh
mkdir -m 700 ./owner-private-workroom
python3 assessment-disclosure-preflight/private_inbox_workroom.py \
  --private-parent ./owner-private-inbox \
  --room review-001 --room review-002 \
  --private-output-dir ./owner-private-workroom
~~~

The existing separate owner-only 0700 output directory outside the original inbox tree receives the original
board HTML/CSV/JSON and `PRIVATE-inbox-actions-template.csv`. It checks all
selected original rooms before exposing any output filename; all four new
files are published together and none overwrite existing output. This is the
preferred operator entry point; the original board-only and prepare-only
commands remain available when separate outputs are intentionally wanted.
An explicit `--full-reopen` adds the original interactive native HUMAN
re-admission for every selected room, but never confers authorization.


The original [PRIVATE multi-room portfolio](./PRIVATE-INBOX-PORTFOLIO.md)
generates owner-private `PRIVATE-inbox-portfolio.json`, containing only
ephemeral input-order slots, A/B/HOLD counts and literal false authority flags.
The exact JSON bytes (not original source evidence) become the SHA-256 bound
local discussion source for this tool.

**Prepare a fresh HUMAN worksheet:** in an existing 0700 destination that
does not already contain these filenames:

~~~sh
python3 assessment-disclosure-preflight/private_inbox_actions.py prepare \
  --board ./owner-private-board/PRIVATE-inbox-portfolio.json \
  --private-output-dir ./owner-private-discussion
~~~

The new `PRIVATE-inbox-actions-template.csv` is owner-only 0600, contains one
UNREVIEWED + UNASSIGNED row per original slot, and neither source notes nor
original customer/target identifiers. Copy/edit it locally in a trusted
spreadsheet or text editor, maintaining the **exact original six columns,
all original slots and exact board SHA**. Store the edited CSV as owner-only
0600 in existing PRIVATE storage before finalization. HUMAN stages are
`UNREVIEWED`, `NEEDS_INPUT`, `IN_PROGRESS`, and
`DISCUSSION_COMPLETE_NO_RELEASE`; proposed roles are `UNASSIGNED`,
`SECURITY`, `PRIVACY`, `CLIENT_OPERATIONS`, or `PLATFORM`.

The status `DISCUSSION_COMPLETE_NO_RELEASE` requires explicit question and
next-action text; it is **not** evidence approval or mitigation verification.
The status `UNREVIEWED` must have no proposed role or copied notes. HUMAN
questions/actions are restricted to bounded text and rejected if they
contain Unicode category-C controls/format characters (including zero-width,
bidi, BOM, private-use, surrogate or unassigned characters), Unicode line or
paragraph separators, or a formula prefix after NFKC normalization. This
catches compatibility disguises such as fullwidth equals before spreadsheet
interpretation, while retaining ordinary international text. The browser
Studio applies the same fail-closed rule, but the unchanged native
`finalize` is authoritative: a hand-edited CSV that bypasses the browser is
rejected too. This is a narrow export-boundary guard, not a guarantee that all
spreadsheet clients are safe and not a general secret-redaction claim.
HUMAN notes are NEVER treated as authenticated assignments or sent automatically.

Before editing, the original unmodified template can also be re-admitted
**without writing any file**:

~~~sh
python3 assessment-disclosure-preflight/private_inbox_actions.py reopen-template \
  --board ./owner-private-board/PRIVATE-inbox-portfolio.json \
  --private-output-dir ./owner-private-discussion
~~~

`reopen-template` reconstructs the exact source-bound original template
and accepts only the single expected output file in an owner-owned 0700
directory, as a regular, unlinked owner-owned 0600 file with identical bytes.
An extra file, symlink, wrong owner/mode, altered original board or changed
template fails closed. Store editable copies in **separate** private folders;
the original template reopen intentionally rejects extra copies.

## Edit the original template with the complete offline HUMAN browser Studio

Open [private-inbox-action-studio.html](./private-inbox-action-studio.html)
locally in an owner-controlled browser and import the original
`PRIVATE-inbox-actions-template.csv` from native `prepare`. The Studio
requires the exact complete original six-column layout, one SHA-bound
original row per original input slot in source order, a literal valid stage
and suggested role, and bounded safe single-line HUMAN notes. It supports
filters for open, in-progress and completed discussions **without omitting
any hidden row from the full export**. Bulk-propose a status and/or discussion
role for only currently visible slots after explicit confirmation; the full
proposed batch is validated before any row changes, and a single Undo restores
the pre-batch values until an individual row edit invalidates it. If any
proposed combination violates the original worksheet rules, the entire batch
is refused. All editing stays in memory:
there is no fetch, localStorage, telemetry, auto-routing, scanner or model.

Select **Prepare complete PRIVATE HUMAN CSV preview** to see full original-slot
counts by proposed stage/role and whether HUMAN questions/next actions are
present. The preview contains no note text; it covers every original slot even
when filters hide cards. Explicitly select **Confirm and download full CSV**
to request the download. Any HUMAN row edit or bulk update invalidates the
preview and requires a fresh one. Manually move the browser download to
owner-controlled 0600 storage. A browser-generated CSV and its SHA do not prove
successful persistence or original producer identity;
reopen and finalize using the original *native* strict source-binding below.
A cancelled or invalid editor source yields no valid native approval or output.
The old original contents are not silently carried forward when importing a
different file.

### Compare a prior saved HUMAN revision (privacy-minimal)

The browser Studio can also compare a previous complete edited six-column CSV
against the current in-memory draft. Select the prior CSV and choose **Compare
prior vs current draft**. Both revisions must admit the same original board SHA,
complete original slot count/order, all HUMAN stages/roles and note constraints.
The comparison refuses different source bytes, incomplete or malformed rows,
invalid current edits, and oversized/malformed UTF-8 input. Every later edit,
bulk proposal or Undo invalidates the displayed delta; the export rechecks the
exact current worksheet bytes before downloading.

The changed-only table shows stage/role values and whether the question or next
action changed, but never displays the text itself. Optional delta CSV and
scriptless HTML omit all question/action contents, source hashes, source filenames
and identities; it includes only slot ordinals, changed-field names, stage/role
values, boolean text-change flags and explicit false chronology/source/consent/
authorization/release fields. “Prior/current” is operator-supplied ordering,
not authenticated chronology or a signed audit trail. Keep this output private
and continue to use the original native finalizer for source-bound admission.

**Finalize a separate PRIVATE operator report:**

~~~sh
python3 assessment-disclosure-preflight/private_inbox_actions.py finalize \
  --board ./owner-private-board/PRIVATE-inbox-portfolio.json \
  --human-csv ./owner-private-discussion-edits/HUMAN-actions.csv \
  --private-output-dir ./owner-private-final-discussion
~~~

Finalization generates 0600 source-bound scriptless HTML, complete CSV and
original source-free JSON in an existing owner-only 0700 output directory.
All fields and original slot membership must re-admit **atomically** before
exposing any output name. Existing target names are refused rather than
overwritten; ordinary file-publish failure rolls back any new names. Like
the original human publisher this is not a power-loss filesystem transaction.

**Read-only reopen of a previously finalized private action set:**

~~~sh
python3 assessment-disclosure-preflight/private_inbox_actions.py reopen \
  --board ./owner-private-board/PRIVATE-inbox-portfolio.json \
  --human-csv ./owner-private-discussion-edits/HUMAN-actions.csv \
  --private-output-dir ./owner-private-final-discussion
~~~

This reconstructs the exact HTML/CSV/JSON bytes and checks **the entire saved
three-file inventory** and all bytes without rewriting. It requires an
owner-owned 0700 directory containing exactly three expected owner-owned
regular 0600 files (with no symlink or hard-link aliases). Unexpected extra
files, changed board, missing/reordered HUMAN rows, an invalid stage/unsafe
note, wrong permissions or altered report bytes return HOLD (3).
Normal completion is REVIEW_ONLY (2), never approval or release.
The same fail-closed custody boundary is shared with `reopen-template`
and `reopen-compare`: byte equality proves local preservation only, not a
trusted origin, original source authenticity, consent or approval.

## Security and scope

Original client evidence, HUMAN reviewer notes, domain authority, scanner
scope, authenticated separate client/operator consent, action-time revocation,
approval and vulnerability remediation proof are NOT part of the source-free
board. Source-free does NOT mean anonymous: small-cohort counts and HUMAN
discussion may be identifying, so keep the entire workroom owner-private.
A source-free board can be tampered with; an unsigned local SHA establishes
only equality to the supplied bytes, not identity. The whole original
PRIVATE HUMAN receiving room must still be read-only re-opened separately
using `private_reopen.py` and, where needed, the original in-browser
reconciliation. No HUMAN action field can override required exact-head hosted
and registered named VPS CI, original source-owner/privacy/security/browser
review, issues #177/#182/#829, actual separate current authenticated
client/operator consent with revocation on use and explicit HUMAN GO.


## Native comparison (without opening a browser)

For an owner-only, source-bound CLI comparison of two saved complete worksheets,
create a new existing private output directory and run:

~~~sh
mkdir -m 700 ./owner-private-revision-delta
python3 assessment-disclosure-preflight/private_inbox_actions.py compare \
  --board ./owner-private-board/PRIVATE-inbox-portfolio.json \
  --prior-human-csv ./owner-private-revisions/prior-actions.csv \
  --human-csv ./owner-private-revisions/current-actions.csv \
  --private-output-dir ./owner-private-revision-delta
~~~

Both complete CSVs must re-admit against the same original board bytes, SHA,
slot order, statuses, roles and safe-note rules before any output is published.
The new 0600 scriptless HTML, CSV and JSON contain only changed slot ordinals,
field names, prior/current stage/role values, question/next-action text-change
booleans and explicit false chronology/source/consent/authorization/release
fields. The actual question and next-action contents, board SHA and filenames
are omitted. "Prior/current" is manually supplied order, not authenticated
chronology. Inputs are read-only; this report is unsigned and non-authorizing.
The destination must be an **empty existing owner-owned 0700 directory**.
Mixed existing files are rejected before publication, ensuring the new report
can later pass the full-inventory read-only reopening contract. The three
report names must not already exist.


### Read-only reopen of the saved revision delta

After generating the three-file report, the native receiver can re-admit it
later without writing or repairing anything:

~~~sh
python3 assessment-disclosure-preflight/private_inbox_actions.py reopen-compare \
  --board ./owner-private-board/PRIVATE-inbox-portfolio.json \
  --prior-human-csv ./owner-private-revisions/prior-actions.csv \
  --human-csv ./owner-private-revisions/current-actions.csv \
  --private-output-dir ./owner-private-revision-delta
~~~

The command rebuilds the expected delta from the currently selected board and
both complete HUMAN CSVs, then requires exactly the three expected report files,
an owner-owned 0700 directory, owner-owned regular 0600 files and byte equality.
Missing/extra files, changed source/HUMAN inputs, wrong permissions, symlinks
or altered report bytes return HOLD. This is unsigned local custody checking,
not trusted identity, authenticated chronology, consent or approval.
