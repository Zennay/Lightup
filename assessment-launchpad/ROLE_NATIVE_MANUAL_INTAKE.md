# Keep HUMAN conflict provenance in the native next-round workroom

**LightUp INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.**

The offline conflict resolver previously produced a complete HUMAN worksheet
which operators had to import using the generic `advance.py --responses`
mode. That workflow could not preserve the source-bound manual choice ledger
inside the resulting next-round workroom, even when the source packet and
choices were independently available.

The native `advance.py --conflict-resolved-dir` import is an **additional**
owner-private, no-network HUMAN collaboration mode. It requires ALL the
following exact original inputs together, without falling back to a generic
JSON-only accept:

* The original 5-file private lab Launchpad bundle;
* The same manually ordered 2–8 original HUMAN rounds, with the last supplied
  through `--previous-round-dir` and earlier ones through
  `--earlier-round-dir`;
* The original 2–5 complete selected-role return packets, **in the exact
  originally resolved order**, with repeated `--conflict-return-dir`;
* The original completed 0600 explicit manual packet choice CSV, passed as
  `--conflict-decision-file`;
* The exact original four-file 0600 resolved conflict output, passed as
  `--conflict-resolved-dir`.

Each source file must remain owner-only, in its own 0700 directory; the
published result must be an independently created **empty** owner-owned 0700
directory. All selected-role packets are re-admitted against the original
source, original selected slot order, and original self-reported HUMAN
rounds. The manually resolved four-file output is recomputed **byte for byte**
from the original decisions; a mismatched or missing ledger, decision, source
or human round causes HOLD. Nothing trusts its own context JSON as an
independent credential or an identity attestation.

## Create a source-bound next HUMAN round

```sh
mkdir -m 700 ~/private-resolved-human-workroom
python3 assessment-launchpad/advance.py \
  --bundle-dir ~/private-lab-launchpad \
  --earlier-round-dir ~/private-human-round-01 \
  --previous-round-dir ~/private-human-round-02 \
  --conflict-return-dir ~/private-owner-return-first \
  --conflict-return-dir ~/private-owner-return-second \
  --conflict-decision-file ~/private-decisions/manual-choices.csv \
  --conflict-resolved-dir ~/private-conflict-result \
  --output-dir ~/private-resolved-human-workroom
```

The workroom contains all existing PRIVATE HUMAN round/editor/routing,
original-source history and delta artifacts, plus the new
`human-manual-conflict-review/` containing **only**:

* A scriptless CSP-pinned PRIVATE HTML of original ordinal, suggested HUMAN
  role, manually chosen original packet, eligible packet options, chosen
  HUMAN stage and PRIVATE-note-changed yes/no.
* The original byte-bound owner PRIVATE decision ledger CSV.
* The original source-bound context JSON with SHA-256 fingerprints.
* A new CSP hash-pinned, offline, printable PRIVATE HUMAN next-action HTML
  with local filters for suggested role, response status and suggested action.
* An owner-private source-minimal action CSV showing every original slot,
  prioritizing missing HUMAN replies and preserving fixed, non-authorizing
  self-reported stage-derived actions without endpoint URLs or note text.
* An owner PRIVATE text guide.

The full source-bound HUMAN worksheet, including every selected and
non-selected role's confidential notes, exists **only** in `human-round/`
rather than being duplicated inside the manual decision review. Never host
or forward the full workroom or recipient notes.

The local `OPEN-NEXT-ROUND-PRIVATE.html` landing page links to the new
conflict decision desk and the new local action-worklist screen. The
decision desk is an operator record of which submitted
self-reported packet was chosen, **not** evidence of identity, permission,
client/operator consent, remediation success or HUMAN GO.

## Exactly reopen the workroom without writing

Provide every original source input **again**, unchanged and in the same
argument order, replacing `--output-dir` with
`--verify-workroom-dir ~/private-resolved-human-workroom`. This re-admits
the original conflict resolver output, complete selected-role returns,
manual choices and original source before regenerating every published
workroom file for exact comparison.

If the original conflict return dirs, completed manual choice CSV and
resolved four-file original output are omitted, the presence of
`human-manual-conflict-review/` forces an explicit HOLD on reopen.

This mode executes no scanner, model, network request, target operation or
permission/grant side effect. All original CI, permanent registered VPS
requirements, independent privacy/security review, authenticated separate
client/operator consent with action-time revocation, source owner approval
and explicit HUMAN GO remain unsatisfied and mandatory.
