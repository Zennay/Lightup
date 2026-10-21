# LightUp PRIVATE HUMAN proposed team conversation desk

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an offline
operator-authored **proposal** for internal HUMAN discussion, never an
authenticated actual assignment, grant, client consent or privacy approval.
Do not transmit generated artifacts or run any scan.

## Source prerequisites

Use the **original** completed masked-note HUMAN packet, the original
2–8 completed HUMAN sensitivity reviewer submissions in the originally
chosen order, the unchanged PRIVATE selected-discussion reception room,
and the exact 2–8 completed HUMAN action packets and history room from
the [PRIVATE HUMAN action workroom](PRIVATE-DISCUSSION-ACTIONS.md).
All input files/directories must be ordinary owner-private 0600/0700,
outside the source checkout. No source discovery or network calls occur.

## 1. Prepare the source-bound offline HUMAN team proposal editor

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-team-prepare \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --history-room /private/work/PRIVATE-lightup-human-action-history-ROOM \
  --private-parent /private/work
```

Native preparation reopens every original source/reviewer/received selection
and completed HUMAN action history before creating the new exclusive
0700 private draft. The resulting fully offline SHA-256 CSP-pinned
`PRIVATE-HUMAN-team-editor.html` displays **original source ordinals**
and latest manually declared HUMAN next-action statuses, never raw
or masked note text, prior PRIVATE human questions or source hashes.

Every original selected position starts `UNASSIGNED`. A human may propose
one of `SECURITY`, `PRIVACY`, `CLIENT_OPERATIONS`, `PLATFORM`, or leave
`UNASSIGNED`. A bounded PRIVATE comment is optional and must not
contain credentials. Even the word "assigned" is never a real owner identity
or team permission. The Studio exports a **complete** selected-original
`PRIVATE-HUMAN-team-proposals.csv` locally, with zero server calls.

## 2. Complete a separate PRIVATE proposal packet

Move the browser download into an owner-private 0600 ordinary file before
using the original native finalizer:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-team-finalize \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --history-room /private/work/PRIVATE-lightup-human-action-history-ROOM \
  --draft-room /private/work/PRIVATE-lightup-human-team-draft-ROOM \
  --completed-csv /private/work/PRIVATE-HUMAN-team-proposals.csv \
  --private-parent /private/work
```

Finalization independently reopens the original source/reviewer/round packets
and demands the unchanged canonical source-bound draft/Studio/template plus
the exact original ordinal roster and 3-field CSV grammar. Noncanonical,
unsafe, missing, duplicated or reordered rows HOLD before output.

A new exclusive PRIVATE 0700 room contains only owner-private 0600
`PRIVATE-HUMAN-team-proposals.csv`, unsigned original-bound receipt and
scriptless grouped `PRIVATE-HUMAN-team-briefing.html`. The HTML withholds
all PRIVATE human comment text. All human team proposals remain merely
proposals. Preparation exits REVIEW_ONLY (2). Completion deliberately
exits HOLD (3), even when files are created successfully.

## 3. Reopen a completed PRIVATE proposed-team packet, read-only

Use the same original completed HUMAN source, original reviewer list and
manually ordered action round paths used when producing the packet:

```sh
python3 private-assessment-notes/notes.py sensitivity-discussion-team-reopen \
  --completed-packet /private/work/ORIGINAL-completed-packet \
  --review /private/work/FIRST-completed-review \
  --review /private/work/SECOND-completed-review \
  --room /private/work/PRIVATE-lightup-human-discussion-ROOM \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-1 \
  --final-room /private/work/PRIVATE-lightup-human-action-final-ROUND-2 \
  --history-room /private/work/PRIVATE-lightup-human-action-history-ROOM \
  --team-room /private/work/PRIVATE-lightup-human-team-proposals-ROOM
```

This does not modify or publish data. It reopens each original source-
and reviewer-bound HUMAN action round, checks the stored complete PRIVATE
proposed-team CSV, recomputes the canonical unsigned private receipt and
demands byte-identical scriptless proposed-team briefing. Missing, altered,
stale or reordered originals HOLD. Successful local reopening still exits
HOLD (3), and gives no real team assignment, reviewer authentication,
consent or recipient permission.

## No real ownership or release

This creates no authenticated team or recipient, no service ticket, no
scheduling, email, external handoff, real assessment authorization, client
or operator consent, evidence of a verified fix or privacy clearance.
Original required exact-HEAD hosted/permanently named VPS CI, independent
source-owner/security/privacy/browser review, #177/#182/#829, separate
authenticated current client and operator consent incl. action-time
revocation and explicit HUMAN GO remain mandatory. Do not merge or deploy
the draft branch before these original gates are actually satisfied.
