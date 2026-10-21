# LightUp PRIVATE HUMAN inbox actions

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This companion is a
local manual task sheet for a *previously created* source-free PRIVATE
multi-room inbox board. It does **not** execute an assessment, authenticate
a real customer/reviewer, verify findings, assign teams, grant consent,
release reports, scan targets or contact a network.

## Workflow

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
questions/actions are restricted to bounded text (no spreadsheet formulas)
and are NEVER treated as authenticated assignments or sent automatically.

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

This reconstructs original exact HTML/CSV/JSON bytes and compares all three
PRIVATE saved outputs without rewriting them. A changed source-free board,
missing/reordered HUMAN row, invalid stage or unsafe note, mismatched receipt,
unsigned output drift or missing private source results in HOLD (3).
Normal completion is REVIEW_ONLY (2), never approval or release.

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
