# PRIVATE HUMAN selection changes — original-source-bound, offline only

The native `action_selection_compare.py` compares **two separately downloaded**
PRIVATE selected-action CSVs against the **same currently re-admitted original**
five-file Launchpad packet, manually ordered 2–8 HUMAN round folders, and
1–5 selected-role return folders. It is a local, unsigned selection-membership
comparison; not authenticated source provenance, not time chronology, not
a finding or remediation verdict, not consent, grant, scan or HUMAN GO.

## Operator workflow

In the offline browser action desk, select desired slots, click
**Download selected rows as PRIVATE CSV**, and move the file into an
owner-owned mode-0700 folder. After HUMAN choices are changed, export a
second snapshot into another owner-owned mode-0700 folder. Keep each input
CSV mode 0600 and preserve every original source packet byte.

```sh
mkdir -m 700 ~/private-human-selected-before ~/private-human-selected-after
mkdir -m 700 ~/private-human-selection-diff
chmod 600 ~/private-human-selected-before/lightup-PRIVATE-human-actions-selected.csv
chmod 600 ~/private-human-selected-after/lightup-PRIVATE-human-actions-selected.csv
python3 assessment-launchpad/action_selection_compare.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --before-csv ~/private-human-selected-before/lightup-PRIVATE-human-actions-selected.csv \
  --after-csv ~/private-human-selected-after/lightup-PRIVATE-human-actions-selected.csv \
  --preview-only
```

Preview prints counts and fixed-vocabulary aggregates only. No source slot
rows, endpoint URL, private note text, source path or SHA enters this output.
Add `--suggested-role SECURITY_REVIEWER` (or any original fixed role) for a
role-minimal comparison: **both complete original selected CSV files and all
source packets are still admitted first**; only the separately published
change rows, role/action aggregates and counted selected slots are filtered.
This never verifies the proposed recipient identity. An empty selected-role
comparison is HOLD. The role-only JSON and HTML report this-role before/after
counts separately from the original all-role totals. Repeat the identical
optional role for preview, output and read-only reopen; default/unfiltered
output remains byte-compatible. A browser-local selection-diff preview is also
available before Apply/Replace. With a prior CSV loaded and one suggested role
selected, the browser action desk offers **Download selected-role-only
differences CSV**. It includes only slots in that role occurring in either
selection; the import preview shows role-only current/imported counts and slot
ordinals before export. Other display filters do not narrow the role-only export.
The all-role export remains available. Neither browser export replaces the original selected-action CSVs
required by this native source-bound comparator.

To create the four-file PRIVATE native packet, repeat the same command but
replace `--preview-only` with
`--output-dir ~/private-human-selection-diff`.

It writes *exclusively* into an already existing, empty, owner-owned mode-0700
folder; its four artifacts have mode 0600:

- `lightup-lab-human-selection-diff-private.html`: standalone scriptless,
  network-blocked CSP human selection-change view and HUMAN role/action matrix.
- `lightup-lab-human-selection-diff-private.csv`: fixed enum / original-local
  ordinal rows: `NEWLY_SELECTED`, `NO_LONGER_SELECTED` or
  `UNCHANGED_SELECTION`. CSV is not an authenticated return packet.
- `lightup-lab-human-selection-diff-counts-private.json`: bounded HUMAN
  membership counts, per-role/per-action breakdown, all authority flags false.
- `START-HERE-HUMAN-SELECTION-DIFF-PRIVATE.txt`: source-minimal handling guide.

Reopen the existing packet **without writing** by repeating the exact source,
round, role-return and before/after CSV arguments, changing the final switch
to `--verify-output-dir ~/private-human-selection-diff`. Any changed original,
file contents, unexpected extra file, missing owner-protected output, changed
source membership or source/output path overlap returns HOLD. The original
source is re-admitted again immediately before publication.

The two selection CSVs must be canonical UTF-8, CRLF, exact original worklist
schema, distinct ordered original source slots with all six fixed-value cells
byte-for-byte matching the same freshly rebuilt source worklist. This tool
never copies original endpoint URLs, note text, reviewer name, local source
path or original SHA digest into output. Original source-slot ordinal and
HUMAN role/action combinations may still identify people, so all four
artifacts remain **PRIVATE unencrypted files** and require legitimate
recipient authorization outside this tool.

`UNCHANGED_SELECTION` means a slot appears in both operator-supplied lists;
it does **not** mean the assessment is unchanged, safe or remediated.
`NO_LONGER_SELECTED` is not evidence that any real issue is closed.
The operator-defined before/after ordering is not authenticated chronology.
No scanner, target connection, network call, review decision, account grant,
file sharing, deploy or HUMAN GO occurs.
