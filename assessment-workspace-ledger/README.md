# LightUp · PRIVATE Assessment Workspace Ledger

**Incubate / M3-M7 PLAN-LAB ONLY · DRAFT/HOLD · NEVER AUTHORIZATION**

This new-only module makes already-produced private assessment workroom packages **reopenable**. A human operator can snapshot 1–12 existing owner-only packages, detect byte-level file changes before continuing HUMAN-only decisions, and compare a new snapshot to the previous one without interpreting missing evidence as a fix.

The module does not parse findings as verified, change any original producer, run tests/scans, contact targets, touch scope/grants, grant consent, send anything, or delete old packages.

## Complete offline flow

Requires Python 3 standard library. Operate on a trusted machine with explicit owner-private folders **outside the checkout**. Existing private kit directories and every nested file/directory must be owner-only. Symlinks, hardlinks, unexpected filesystem entries and unstable file contents are refused.

1. Create an owner-only 0700 destination folder outside the source checkout.
2. Snapshot one or more existing original PRIVATE kit folders:
    python3 assessment-workspace-ledger/ledger.py capture --kit /private/original-briefing-kit --kit /private/original-review-kit --label "Lab briefing" --label "Human review" --private-parent /private/private-ledgers
3. The CLI prints a new private output directory. Open its OPEN-PRIVATE.html locally to view source-minimal kit counts and changes. Open REVIEW-IN-BROWSER.html, explicitly choose its adjacent ledger.json in the file picker, set HUMAN-only stages/owners/questions, then download HUMAN-review.csv. No service/browser storage/network is used.
4. Re-admit every original file before continuing:
    python3 assessment-workspace-ledger/ledger.py reopen --ledger /private/private-ledgers/PRIVATE-lightup-ledger-EXAMPLE/ledger.json
5. Finalize the human-edited CSV only if original source files still match:
    python3 assessment-workspace-ledger/ledger.py finalize --ledger /private/private-ledgers/PRIVATE-lightup-ledger-EXAMPLE/ledger.json --plan /private/private-ledgers/PRIVATE-lightup-ledger-EXAMPLE/HUMAN-review.csv --private-parent /private/private-ledgers
6. For a fresh snapshot against the *same explicit kit paths*, repeat capture with --previous /private/private-ledgers/PRIVATE-lightup-ledger-EXAMPLE/ledger.json. Added/removed/modified source-file counts are flagged as human-review HOLD, **not verified remediation**.

**Exit 2 = PRIVATE REVIEW_ONLY** when no differences are observed. **Exit 3 = HOLD** on any input refusal, HUMAN finalization, or observed changes. A changed snapshot still creates a *new* exclusively private inventory to support follow-up; previous snapshots are not deleted or overwritten.

## Product artifacts

- ledger.json: PRIVATE original absolute paths, bounded file inventory, size and SHA-256 per file, per-kit digest, previous snapshot SHA and literal all-false authority flags; this contains sensitive paths and MUST NOT be shared as an anonymous export.
- OPEN-PRIVATE.html: scriptless inventory with kit ordinal, chosen HUMAN label, file/byte totals and optional byte-diff counts. Original file paths are omitted, but it is still PRIVATE.
- HUMAN-review.csv: original-byte-bound HUMAN decision template, editable locally.
- REVIEW-IN-BROWSER.html: complete CSP-hash-pinned single-file offline editor with local original ledger import, HUMAN-only stage selection, owner/question fields, downloadable PRIVATE CSV and no remote I/O or persistence. Human stages: needs_review, owner_followup, hold, reference_only.
- HUMAN-private.html plus HUMAN-only.json: new separate original-snapshot-bound HUMAN packet, always **HOLD**, with no originals copied and no authority asserted.

Native Python independently re-admits the bounded original ledger and re-hashes every original kit file before accepting the HUMAN decision CSV. Malformed or duplicate JSON keys, mismatched source ordinals or hashes, unexpected CSV fields, unknown stages, formula-prefixed spreadsheet entries, source changes, symlinks and public-permission files fail closed. Browser-local editing is a convenience only, never an original-source verifier.

Limits: 1–12 kits, <=256 files per kit, <=64 MiB each kit, <=32 MiB per individual file, <=256 MiB combined, max depth 5, <=1 MiB ledger JSON, <=64 KiB HUMAN CSV. Existing owner-private input folders, owner-only 0700 output parent, 0700 exclusive generated folders and 0600 output files. No implicit scans, no original source modification and no overwrites.

## Historical comparison when source kits are no longer present

The self-contained companion command compares two previously stored original
private ledger.json snapshots **without reopening the original source kits**.
It is useful for private human handoff or archival review after moving to another
trusted machine:

    python3 assessment-workspace-ledger/compare.py --before /private/ledger-before/ledger.json --after /private/ledger-after/ledger.json --private-parent /private/private-ledgers

The original slot paths and ordinal ordering must match exactly, so unrelated
packages cannot be compared as if they were revisions. It produces a fresh
owner-only 0700 package with PRIVATE-historical-comparison.json, a printable
OPEN-PRIVATE.html and a separate PRIVATE-HUMAN-comparison-template.csv. The
comparison displays only counts of added, removed, changed and unchanged kit
files, not source filenames, file contents or target identifiers in its HTML.
Its source ledger SHA-256s are **unsigned** and remain PRIVATE. No original
source files are reopened or authenticated; the report never claims they
still exist or were remediated. Changes => HOLD 3, no differences => REVIEW_ONLY 2,
never PASS.

A browser-exported CSV often lands in a Downloads folder with permissive
filesystem permissions. **Before** passing it to native finalize, move the file
to an owner-only (0700) local folder and ensure the CSV itself is mode 0600;
native input admission intentionally rejects public-readable files.

## Trust and release

SHA-256 inventories are unsigned. They do not authenticate the producer, source client, original data, reviewer, verified finding, remediation or current consent. A person who can modify both input and unsigned manifest may forge a mutually consistent statement. Removed artifacts do **not** prove a fix or retest. Small counts can identify confidential matters and must remain PRIVATE.

Notion posture remains **Incubate M3/M7 PLAN/LAB ONLY**. Draft/HOLD software only: no main merge, deploy, scans, live targets or automatic external handoff. Exact-head GitHub-hosted and permanently registered named VPS CI, original source-owner approval, independent privacy/security/browser review, original #177/#182/#829, separate authenticated current client and operator consent with action-time revocation, and explicit HUMAN GO remain mandatory. No QA, regression or test suites are added or invoked.
