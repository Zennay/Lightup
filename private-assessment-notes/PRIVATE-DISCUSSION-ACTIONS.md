# PRIVATE selected HUMAN discussion actions

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a local,
owner-private, non-authorizing assessment review workroom; never a grant,
privacy clearance, fix attestation or client communication.

## Workflow

Start with the original **completed HUMAN source packet**, the original
**2–8 completed sensitivity reviewer packets** (in the same explicit
manual order), and the previously received PRIVATE selected-discussion room.
See the parent [review and receiver guide](README.md) for the original
`sensitivity-discussion-receive` and `sensitivity-discussion-reopen` steps.

Use an existing directory outside the source tree which is owner-only 0700,
and keep each original artifact in its own owner-private directory. Only
the owner's local browser should open generated HTML.

### 1. Prepare a new HUMAN follow-up draft

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-prepare \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --private-parent /private/work
```

This creates a fresh 0700 private action-draft folder with a 0600
source/selected-row binding, complete blank template CSV and source-bound
CSP-pinned HTML Studio. No original note contents or free HUMAN notes are
embedded. The Studio shows original ordinal-only Boolean concern reasons,
including PRIVATE note-disagreement flags, and offers visual filters.
Filtering does not remove any original selected row from export.

Each selected source starts **PENDING**; a human can explicitly choose
**DISCUSS**, **REQUEST_OWNER_CONTEXT**, or **WITHHOLD** and an optional
bounded PRIVATE question. The Studio accepts a previous complete canonical
locally exported CSV using **Restore previous complete local PRIVATE HUMAN
action CSV**. Every ordinal, field and row must match before the operator
confirms replacing their unsaved form. No data is saved automatically.

### 2. Explicitly finalize the complete local CSV

Export the **complete PRIVATE HUMAN next-step CSV**, move it into an
owner-controlled 0600 file (browser downloads do not ensure this mode),
and run:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-finalize \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --draft-room /private/work/PRIVATE-lightup-human-action-draft-ROOM \
  --completed-csv /private/work/PRIVATE-HUMAN-discussion-actions-completed.csv \
  --private-parent /private/work
```

Native admission independently reopens the ORIGINAL source and completed
review packets, original selected receiver, unchanged action editor/template
and source bound receipt. It requires a complete canonical CSV with all
original selected ordinals, allowed stages and bounded safe HUMAN questions.
A fresh 0700 private room contains only owner-private 0600 receipt, full
actions CSV and source-minimal printable HTML. The HTML deliberately withholds
questions; the CSV contains them. No source data, raw findings, target URLs,
reviewer identities or source digests appear in the printable page.

### 3. Read-only reopen of the completed HUMAN action packet

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-reopen \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROOM
```

Reopening independently validates every original PRIVATE source and reviewer
packet, selected reception, full action CSV, receipt and derived HTML
against exact original content. Missing or altered output is refused,
without writes. The manually ordered reviewer slots do **not** authenticate
human reviewer identities; identical submitted content is not independent
reviewer evidence. A byte hash is unsigned and not an authentic signature.

## 4. Compare two to eight completed HUMAN action rounds privately

After separately finalizing multiple completed HUMAN action rooms against the
SAME received original review selection, a human operator can assemble an
entirely offline, manually ordered action history without copy/pasting any
original confidential question text:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-history \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --private-parent /private/work
```

The original completed packet, all reviewers, exact selected discussion
receipt and each finalized action receipt/HTML/CSV are independently
reopened BEFORE a new 0700/0600 history room is prepared. The order is
manually chosen; it is **not** authenticated chronology. Duplicated
directories are refused; exact duplicate action content is explicitly
counted, not considered independent follow-up. Outputs include a printable
scriptless HUMAN status trajectory, an ordinal-and-round CSV with
PRIVATE-question-*changed* flags (no question text), and an unsigned
source-bound private receipt.

The same owner-private history room also includes the offline
`PRIVATE-HUMAN-action-history-studio.html` browser navigator: filter by
declared HUMAN round, selected original ordinal, literal status changes,
private question-*changed* flags or WITHHOLD. A local selected-only CSV
download contains only filtered original positions and Boolean human changes.
The original complete source-bound history and receipt stay unchanged.
This is a private discussion convenience, **never** a full review or release.

This is not a reduction-in-risk measurement or verified remediation
certificate: statuses and questions may change for reasons unrelated to
the actual security/privacy of an asset. Successful local creation
still returns **HOLD (exit 3)**. Nothing is sent or granted.

### PRIVATE latest-HUMAN follow-up attention desk

New source-bound history rooms also contain
`PRIVATE-HUMAN-latest-focus.html` and
`PRIVATE-HUMAN-latest-focus.csv`. This is a printable, scriptless,
strictly source-minimal original-ordinal follow-up desk sorted by the
**latest declared HUMAN next action**, not by any inferred security
severity. The desk distinguishes WITHHOLD, REQUEST_OWNER_CONTEXT,
DISCUSS and PENDING for every originally selected source, along with
how many human next-action and private-question **content** changes
were declared in manually ordered rounds. Actual question text,
masked notes, client details and source hashes do not enter these
overview artifacts.

The native original-byte source receipt now includes
`latest_human_focus_original_bound`. New rooms require both exact
focus files when read-only reopening. Previously saved genuine history
rooms remain independently readable under their older canonical
receipt shape, without falsely claiming they contain a new focus desk.
The printable history also now uses the **actual original source
ordinal** (e.g. #2 and #9), not the index within the selected subset.
The earlier index-labelled HTML remains strictly acceptable only
inside its originally produced older history receipt form.

The focus desk is PRIVATE HUMAN discussion, not a to-do assignment,
risk ranking, remediation proof or client authorization. Follow up
through the original native finalizer, never directly through a
receipt or dashboard.

### Source-bound selected HUMAN history handoff (native)

The offline action history Studio can export only the currently visible,
source-minimal original-ordinal HUMAN rows as
`PRIVATE-HUMAN-selected-action-history.csv`. This file is not a full
original HUMAN review. To receive that file as a separate confidential
discussion packet, place the downloaded CSV in a 0600 owner-private file
and invoke the ORIGINAL native receiver using exactly the original
completed source packet, original 2–8 reviewer packets, the original
selected discussion, the original chronological final HUMAN action rooms,
and the exact generated history room:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-history-receive \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --history-room /private/work/PRIVATE-lightup-human-action-history-ROOM \
  --selected-csv /private/work/PRIVATE-HUMAN-selected-action-history.csv \
  --private-parent /private/work
```

The native receiver independently reopens the exact original history
against all original completed reviews and rounds, then demands the original
browser's exact selected CSV header, quoting, order, fields and original
HUMAN stage/question Boolean values. Stale, altered, duplicate, foreign,
reordered or empty selections refuse BEFORE any output directory is created.
A fresh PRIVATE 0700 room contains a 0600 canonical selected CSV, unsigned
original-source/custody receipt and scriptless source-minimal printable
human discussion. No original free HUMAN question text is copied into HTML.
This is not permission to share; even successful local work returns HOLD (3).

### Read-only reopen of a received selected HUMAN history

The local selected-original HUMAN history receiver has a separate exact
read-only native reopener. Supply the **same original completed source and
2–8 human reviews**, the same originally received discussion, all original
completed action rounds in the same declared order, the unchanged original
history room, and the resulting local selected-only PRIVATE room:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-history-receive-reopen \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --history-room /private/work/PRIVATE-lightup-human-action-history-ROOM \
  --selected-room /private/work/PRIVATE-lightup-human-history-selection-ROOM
```

The native tool independently re-admits all **original** selected history
rows, their exact private local CSV, canonical unsigned custody receipt
and printable discussion page. Altered, missing, reordered or stale
private files HOLD. It performs no writes and exits HOLD (3), including
when exact source-bound artifacts are intact. It is not an authenticated
identity, approval, verifiable remediation, or right to disclose.

### Prepare the next independent HUMAN round directly from the history room

Each new history room contains a **fresh blank** source-bound
`PRIVATE-HUMAN-action-editor.html`, unchanged native
`PRIVATE-HUMAN-action-template.csv` and exact
`PRIVATE-HUMAN-action-source.json`, in addition to its read-only chronology.
All original selected positions start PENDING with EMPTY questions: previous
WITHHOLD, discussion choices, follow-up notes, consent, identity or apparent
progress are NEVER adopted automatically. Open the blank Studio offline,
make NEW explicit HUMAN choices, save its complete original-position CSV in
an owner-only 0600 file, and use the **unchanged native original**
`sensitivity-discussion-actions-finalize` with
`--draft-room /private/work/PRIVATE-lightup-human-action-history-ROOM`.
The original completed source packet, original reviewers and received
selected discussion room must be the same ones used for the history.

The native finalizer independently verifies the new history-room draft against
original source binding; it writes a separate 0700/0600 PRIVATE action record
and still returns HOLD (3). The chronology itself is not mutated, and it does
not become an authorization or a verified fix. Read-only history reopening
also validates the complete blank next-round editor/template/binding bytes.
The receipt explicitly distinguishes **new** history rooms with a blank
source-bound continuation from older read-only history rooms created before
this workflow existed. The reopener admits both exact historical original
receipt formats against their proper native files, without altering either.
An older history room is not silently promoted into a new continuation room:
prepare a fresh native `sensitivity-discussion-actions-prepare` workroom if
you need a new blank HUMAN next round from that earlier history.

### Read-only original HUMAN chronology reopening

Use the same manually ordered **original** finalized rounds as the previous
history creation and supply the 0700 history output directory:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-actions-history-reopen \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --history-room /private/work/PRIVATE-lightup-human-action-history-ROOM
```

The command re-admits the **actual original completed packet**, every source
review, every complete received action room and original manually ordered
round; then requires exact bytes for saved receipt, full source-ordinal CSV,
printable chronology and CSP-pinned browser Studio. It performs **no writes**
and always returns **HOLD (3)**. Any missing, reordered, changed or stale
artifact refuses reopening. Reopening does not authenticate a reviewer,
prove chronology, verify a security fix or grant disclosure.

## Fixed boundaries

Preparation exits **REVIEW_ONLY (2)**. Finalization and reopening always
exit **HOLD (3)**, including after successful private artifact creation or
reopening. A local HUMAN plan cannot be turned into a completed original
sensitivity review, remediation assertion, scanning authorization or
permission to disclose. Do not upload original private artifacts, notes,
questions, or receipts to issues or public repositories.

No network, model call, scanner, scope, grant, dispatch, background sending,
active target, customer communication or deployment is performed.
Original exact-head hosted and permanently registered named VPS CI,
source-owner review, independent security/privacy/browser review, issues
#177/#182/#829, separately authenticated current client/operator consent
with action-time revocation and explicit HUMAN GO remain mandatory before
any main merge, production deployment or actual client assessment.


## Further LOCAL HUMAN team proposal desk

[Open the original-bound PRIVATE HUMAN team proposal workflow](PRIVATE-DISCUSSION-TEAM-ROUTING.md). A team name is an unauthenticated HUMAN discussion suggestion only; never a real assignment or permission to disclose.
