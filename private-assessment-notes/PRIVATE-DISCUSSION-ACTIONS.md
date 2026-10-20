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
