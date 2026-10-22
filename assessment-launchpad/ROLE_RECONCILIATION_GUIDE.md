# PRIVATE HUMAN role-return reconciliation

**DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY.**
This is an offline operator-only read of fictional or already existing authorized
lab review *records*, not an assessment or permission to contact a target.

## Product workflow

A recipient's voluntarily assigned HUMAN role is not identity authentication.
Previously, separate selected-role packets could be consolidated into the next
workroom, but the operator did not receive a readable review of **which
original local slots were selected, what changed, and which suggested roles
still report pending work**.

The native `role_return_reconcile.py` now admits one to five *complete original
two-file source-bound return packets*, against the same original five-file
Launchpad and two to eight unchanged operator-ordered HUMAN rounds. It
rejects duplicate packet directories and all overlapping source ordinals:
there is no automatic precedence and no risk of merging another role's notes.
Every original packet, receipt, owner-private worksheet, and original lab
source must re-admit, including a second source read immediately before
publication. An unsigned local packet does not authenticate an actual person.

Create the output directory as a new mode-0700 directory owned by the current
user. The source folders and result must all be separate.

```sh
mkdir -m 700 ~/private-human-reconciliation

python3 assessment-launchpad/role_return_reconcile.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --output-dir ~/private-human-reconciliation
```

The result consists of exactly seven exclusive mode-0600 files:

* `lightup-lab-human-return-reconciliation-private.html`: offline,
  scriptless, SHA-256 CSP-pinned table of suggested role, original **local
  ordinal**, prior vs proposed HUMAN stage, and whether a private note changed.
  It does **not** include endpoint URLs, note text, filesystem paths, hashes
  or authenticated reviewer identities. It must still be kept PRIVATE.
* `lightup-lab-human-return-reconciliation-private.csv`: the same
  fixed-vocabulary ordinal/role/stage change matrix, no note text.
* `lightup-lab-human-unreturned-private.csv`: each original local slot that
  did NOT receive a selected-role return in the submitted collection, with
  the last voluntary suggested HUMAN role and HUMAN stage; neither URLs nor
  private note content are included. An earlier HUMAN_REVIEW stage is **not**
  evidence that a human has returned anything. The PRIVATE HTML includes
  a separate attention table for these unreturned slots.
* `lightup-lab-human-role-worklist-private.csv`: every original local slot,
  whether its selected-role return is received, latest suggested HUMAN role
  and stage, private-note-changed YES/NO, and one fixed operator follow-up
  suggestion. Unreturned slots are first: REQUEST_HUMAN_ROLE_REPLY. Returned
  stages map to COLLECT_MISSING_HUMAN_INPUT, SCHEDULE_HUMAN_REVIEW or
  FOLLOW_UP_WITH_HUMAN_OWNER. These are **suggestions**, not new process gates
  or proof that anyone completed a review. The same action queue is visible
  as a separate table in the PRIVATE offline reconciliation HTML.
* `lightup-lab-human-next-actions-private.html`: offline CSP-hash pinned,
  owner-private, filterable and printable HUMAN action worklist. Filter
  source-minimal local original slots by voluntarily suggested role, receipt
  presence, proposed HUMAN next action, self-reported HUMAN stage and whether
  a PRIVATE note was changed. Clear all filters restores the complete local
  view without touching the original packet. The page now shows visible action
  counts and prints **only currently displayed rows**: filtering out a HUMAN
  role or packet must never silently restore its hidden rows in a printout.
  Tick individual original slots or use **Select displayed slots** to add the
  visible rows without clearing earlier selections. **Deselect displayed slots** removes only visible rows; **Clear all selections**
  resets the in-memory queue. **Download selected rows as PRIVATE CSV** exports
  only explicitly selected fixed-vocabulary rows in original source order,
  including selections hidden by the current filter; printing remains limited
  to the visible view. No endpoint URL, private note text, reviewer name,
  original path or digest is included. The saved CSV and any
  printed/PDF copy are **PRIVATE unencrypted recipient artifacts**: operator
  must still authenticate recipients and confirm permission outside this tool.
  Filters and explicit slot selections exist only in memory, not browser storage
  or network; the original complete source worklist CSV is never modified. The workroom's local start
  page links to this view.
* `lightup-lab-human-return-reconciliation-counts.json`: source-free
  overall change counts, suggested-role workload, nonreturned slot totals
  by fixed suggested role/stage, and explicitly negative
  identity/authorization/HUMAN-GO flags. Small cohorts may be identifiable.
* `START-HERE-RECONCILIATION-PRIVATE.txt`: use and safety restrictions.

Read-only replay verifies **exact canonical file inventory and content** from
the original source and the same HUMAN returns, without changing either:

```sh
python3 assessment-launchpad/role_return_reconcile.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --verify-output-dir ~/private-human-reconciliation
```

To actually create the **next** HUMAN round, the original source-bound returns
must still be passed to `advance.py` with matching earlier-round/previous-round
arguments. This reconciliation output never grants access, replaces a reviewer,
approves a remediation or permits a scan.

No network, model, target, grant, consent or active assessment is involved.
Permanent CI, independent privacy/security, authentic client/operator consent
with action-time revocation, original source owner, and explicit HUMAN GO remain
mandatory for release.

## Included automatically in the next-round PRIVATE workroom

When you create the next round with `advance.py --role-return-dir`, the
same source-bound reconciliation is now published **inside** that complete
PRIVATE workroom, under `human-role-reconciliation/`, alongside the next
HUMAN worksheet, editor, routing desk, delta and role handoff.

The scriptless `OPEN-NEXT-ROUND-PRIVATE.html` landing screen now links
directly to the reconciled role/slot changes. All reconciliation artifacts
are regenerated from the exact original source rounds and original
source-bound return packets **before publication**, and every file is
verified during a read-only reopen.

For this **role-return-based workroom**, read-only reopening requires the
unchanged original role-return directories supplied again in precisely the
same order. Omitting them is a HOLD because the aggregate report cannot
independently prove its own provenance.

```sh
python3 assessment-launchpad/advance.py \
  --bundle-dir ~/private-lab-launchpad \
  --earlier-round-dir ~/private-human-round-01 \
  --previous-round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --output-dir ~/private-role-consolidated-round

python3 assessment-launchpad/advance.py \
  --bundle-dir ~/private-lab-launchpad \
  --earlier-round-dir ~/private-human-round-01 \
  --previous-round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --verify-workroom-dir ~/private-role-consolidated-round
```

These are offline HUMAN-only source-consistency operations, never scans
or authorized assessment dispatches. Separate recipients, client and
operator consent, security/privacy review and explicit HUMAN GO are
**not** satisfied by a matching local source receipt.

## Re-admit a filtered browser CSV into an original-source-bound PRIVATE packet

The browser's **Download selected rows as PRIVATE CSV** is deliberately an
*unsigned* local download, not a reviewer credential or review clearance.
For a bounded separate native handoff, put it in an owner-owned `0700` folder,
set the downloaded file to `0600`, and use the NEW `action_handoff.py` CLI.
This command checks every chosen exact row and their original worklist order
against all original Launchpad, HUMAN rounds and selected-role return packets.
A fabricated row, altered original role/status/action, duplicate, reordering,
noncanonical CSV bytes or cross-source selection is HOLD. The six-column
header exactly matches the source worklist, including `latest_suggested_role`.
The HTML and counts JSON summarize five dimensions—role, reply status,
self-reported stage, proposed next action and note-change flag—without private
note content. It never accepts a browser CSV as original evidence or a scope grant.

First run the same source-bound admission without publishing any files:

```sh
python3 assessment-launchpad/action_handoff.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --selected-csv ~/private-selected-human-input/lightup-PRIVATE-human-actions-selected.csv \
  --preview-only
```

This reports only the selected/original slot counts and writes nothing. For
actual publication, use a separate new empty mode-`0700` destination:

```sh
mkdir -m 700 ~/private-selected-human-input ~/private-selected-human-output
mv ~/Downloads/lightup-PRIVATE-human-actions-selected.csv ~/private-selected-human-input/
chmod 600 ~/private-selected-human-input/lightup-PRIVATE-human-actions-selected.csv
python3 assessment-launchpad/action_handoff.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --selected-csv ~/private-selected-human-input/lightup-PRIVATE-human-actions-selected.csv \
  --output-dir ~/private-selected-human-output
```

This publishes exactly four new owner-only `0600` artifacts: original-ordinal
PRIVATE selected CSV, scriptless hash-CSP PRIVATE HTML, a fixed-vocabulary
PRIVATE counts JSON with every authority/consent/release flag explicitly false,
and a local private usage guide. No endpoint, note, recipient name, path or
source digest is included; tiny cohort combinations may still identify people.
The separate source and output folders must not overlap. No file is overwritten.
To reopen **the exact same** source-bound four-file packet without writing:

```sh
python3 assessment-launchpad/action_handoff.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --selected-csv ~/private-selected-human-input/lightup-PRIVATE-human-actions-selected.csv \
  --verify-output-dir ~/private-selected-human-output
```

All original five-file, four-file and two-file source packets are freshly
admitted during creation and read-only reopen; creation also re-admits source
and selection immediately before publication. The source bytes and local
hashes are **unsigned local consistency only**, not cryptographic proof of
reviewer identity, tenant consent, secure sharing, assessment or HUMAN GO.
