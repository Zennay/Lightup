# PRIVATE HUMAN role-return — end-to-end operator workflow

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.**
This is a private local HUMAN collaboration workflow, not a security assessment,
identity proof, client consent, operator authorization, or HUMAN GO.

The original role-filtered handoff is read-only. `role_return.py` completes
that workflow by generating a minimal return CSV, admitting only permitted
human edits, and building a full source-bound worksheet for `advance.py`.
No target, scan, model, or executor is contacted.

## Inputs

Keep the original five-file Launchpad bundle, two to eight complete original
HUMAN rounds, and the exact original four-file `role_handoff.py` packet in
separate owner-private directories. Use the **same** ordered rounds,
`--role`, `--stage` and any `--slot` options as the original handoff.
The script regenerates and compares every byte of the original handoff
against those private inputs, including the voluntary selected-role filter.
A role is **not** an authenticated identity or access-control check.

All input files must remain regular, single-link, 0600 files in owned 0700
directories. Create any output folder empty and owner-private via `mkdir -m 700`.

## Prepare a minimal return

```sh
mkdir -m 700 ~/private-role-return-form
python3 assessment-launchpad/role_return.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --handoff-dir ~/private-role-handoff \
  --role SECURITY_REVIEWER --stage ALL \
  --output-dir ~/private-role-return-form
```

Alongside the template, the producer now emits a source-minimal standalone
`lightup-lab-human-role-return-editor.html`. Open that owner-private file
locally in a browser to edit only selected HUMAN stages and new notes, then
choose **Download PRIVATE role-return CSV**. This editor contains no endpoint
URLs, old notes, other roles, external assets, network access or browser
storage. Its inline code/styles are SHA-256 CSP-pinned. Move the browser's
CSV download into a separate current-user-owned 0700 directory, chmod 600,
and import it through the **native** `--reply-file` gate. The browser cannot
validate identity, consent, scope or original input bytes and its downloads
are not permission-restricted by default.

The private `lightup-lab-human-role-return-template.csv` contains only
selected original slot numbers, that role, fixed HUMAN stage values, a
source-binding SHA-256 fingerprint and **blank** proposed note cells.
It contains neither endpoint URLs nor any pre-existing PRIVATE note
from other roles. A matching SHA-256 is only an integrity fingerprint;
it does not authenticate the sender.

Edit **only** `proposed_human_stage` (NEEDS_INPUT, HUMAN_REVIEW, FOLLOW_UP)
and `proposed_private_note` (maximum 400 characters, no unsafe control or
format characters). Retain all rows in their original order and all other
fields unchanged. Do not use spreadsheet formulas. Keep the edited CSV
offline in its own 0600 file under an owned 0700 directory.

## Import the response

```sh
mkdir -m 700 ~/private-owner-role-return
python3 assessment-launchpad/role_return.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --handoff-dir ~/private-role-handoff \
  --role SECURITY_REVIEWER --stage ALL \
  --reply-file ~/private-replies/review.csv \
  --output-dir ~/private-owner-role-return
```

The owner-private output has exactly TWO files: `lightup-lab-human-role-return-private.json`
(a *full* canonical HUMAN worksheet) and `lightup-lab-human-role-return-context.json`
(a source-bound, unsigned receipt of the exact source rounds, role, selected
slots, original handoff and owner worksheet). Nonselected rows and their notes
are preserved unchanged; only the exact selected role's stage and note
may change. **Never distribute this full worksheet to the role recipient**:
it necessarily contains notes from other roles. All source and reply
bytes are re-admitted before exclusive no-overwrite publication.

To edit on an owner-local terminal without a CSV, instead use
`--interactive` in place of `--reply-file`. The menu prints only slot
ordinals, current stages and old note lengths. Enter retains a current
value, `-` clears a private note. Notes are entered without terminal
echo; interruption/invalid input aborts publication. The full output
file is the same, but retains its private storage requirement.

To reopen and compare deterministically against the original private
inputs, change `--output-dir DIR` to `--verify-output-dir DIR`, and
retain the exact original `--reply-file` when verifying an import.
TTY-only output has no persisted source reply and therefore cannot use
this exact re-open operation.

## Continue through the existing HUMAN advance workflow

```sh
mkdir -m 700 ~/private-next-human-round
python3 assessment-launchpad/advance.py \
  --bundle-dir ~/private-lab-launchpad \
  --previous-round-dir ~/private-human-round-02 \
  --earlier-round-dir ~/private-human-round-01 \
  --role-return-dir ~/private-owner-role-return \
  --output-dir ~/private-next-human-round
```

The --role-return-dir importer additionally re-opens both original files,
all earlier source rounds and the exact selected-role handoff fingerprint,
and refuses changes to non-selected rows, suggested role, ordinals or other
source metadata. This source consistency check is not a cryptographic
identity signature or recipient authentication. For existing unbound
external JSON, --responses remains a distinct manual HUMAN input mode.

When --handoff-role is selected in advance.py, its next-round workroom
now automatically contains BOTH the original selected-role handoff and the
new human-role-reply-form folder with role-minimal PRIVATE offline editor,
blank-note CSV and private guide. The local navigation screen links directly
to the role reply editor. Import its edited CSV into a new owner-only directory
with role_return.py, before starting the following --role-return-dir cycle.

The original rounds remain unchanged. The resulting workroom contains
the next PRIVATE HUMAN round, editor, routing, history, and follow-up
panels as supported by the existing Launchpad. The operator must
separately provide earlier rounds and any previously selected role/slot
handoff arguments to `advance.py` if those outputs are desired.

Nothing here validates reviewer identity, confirms authority/consent,
changes grants, verifies a remediation, or starts an assessment.
All existing source-owner, CI, permanent VPS, privacy/security,
separate client/operator consent, action-time revocation and HUMAN GO
gates remain mandatory.
