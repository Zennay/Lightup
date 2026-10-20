# LightUp · PRIVATE Assessment Workspace Ledger

**Incubate / M3-M7 PLAN-LAB ONLY · DRAFT/HOLD · NEVER AUTHORIZATION**

This new-only module makes already-produced private assessment workroom packages **reopenable**. A human operator can snapshot 1–12 existing owner-only packages, detect byte-level file changes before continuing HUMAN-only decisions, and compare a new snapshot to the previous one without interpreting missing evidence as a fix.

The module does not parse findings as verified, change any original producer, run tests/scans, contact targets, touch scope/grants, grant consent, send anything, or delete old packages.

## Start without assembling commands: one foreground PRIVATE operator console

The independent [console.py](console.py) is a complete guided HUMAN-only
operator interface for the exact same original native functions. Start it
locally from a trusted checkout:

    python3 assessment-workspace-ledger/console.py

Eight console actions provide original kit capture, exact-byte reopen, original-bound
HUMAN CSV finalization, historical change review with private file-level
drilldown, unchanged-source HUMAN continuity, a separate source-free
single-file browser editor export, a native same-source HUMAN revision desk,
and an in-memory status-only local action summary. Every user-selected action runs **once, synchronously**, with no
subprocess/shell, service, queue, background job, network, model, scan,
consent grant, scheduled activity or source deletion. A HOLD (3) keeps the
foreground console accessible so the operator can choose a different safe
function. Nothing is automatically retried; the console itself terminates
with HOLD even if a local software-only action returned REVIEW_ONLY. Sensitive
private file paths are only entered locally and never sent to GitHub/Notion.

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

## Ready-to-use actual offline HUMAN browser application

A complete source-free one-file production artifact has been **built from the
current browser_studio.py renderer and committed**:
[standalone.html](standalone.html). Save a copy in a trusted owner-private
local folder and open it with the browser offline; there is no Python/runtime
dependency for the interactive reviewer interface itself. Explicitly select
your locally generated original private ledger.json using the browser's file
chooser; no user data is embedded in this shipped HTML. All HUMAN decisions
still require the native fail-closed original-snapshot finalize.

## Portable browser-only software build

The independent HUMAN editor is also usable without creating any inventory
first. Produce one standalone source-free HTML file, exclusively without
overwriting a previous copy:

    python3 assessment-workspace-ledger/browser_studio.py --output /private/new-ledger-studio.html

Open it offline with no Python/server/browser storage, and choose an existing
original PRIVATE ledger.json in the local file picker. The output HTML itself
contains no source/customer data or local paths. Keep chosen source files
and exported HUMAN CSVs in owner-only private storage; finalize re-checks
the exact original snapshot in the native CLI.

## Product artifacts

- ledger.json: PRIVATE original absolute paths, bounded file inventory, size and SHA-256 per file, per-kit digest, previous snapshot SHA and literal all-false authority flags; this contains sensitive paths and MUST NOT be shared as an anonymous export.
- OPEN-PRIVATE.html: scriptless inventory with kit ordinal, chosen HUMAN label, file/byte totals and optional byte-diff counts. Original file paths are omitted, but it is still PRIVATE.
- HUMAN-review.csv: original-byte-bound HUMAN decision template, editable locally.
- REVIEW-IN-BROWSER.html: complete CSP-hash-pinned single-file offline editor with local original ledger import, HUMAN-only stage selection, owner/question fields, downloadable PRIVATE CSV and no remote I/O or persistence. Human stages: needs_review, owner_followup, hold, reference_only.
- HUMAN-private.html plus HUMAN-only.json: new separate original-snapshot-bound HUMAN packet, always **HOLD**, with no originals copied and no authority asserted.

Native Python independently re-admits the bounded original ledger and re-hashes every original kit file before accepting the HUMAN decision CSV. Malformed or duplicate JSON keys, mismatched source ordinals or hashes, unexpected CSV fields, unknown stages, formula-prefixed spreadsheet entries, source changes, symlinks and public-permission files fail closed. Browser-local editing is a convenience only, never an original-source verifier.

Limits: 1–12 kits, <=256 files per kit, <=64 MiB each kit, <=32 MiB per individual file, <=256 MiB combined, max depth 5, <=1 MiB ledger JSON, <=64 KiB HUMAN CSV. Existing owner-private input folders, owner-only 0700 output parent, 0700 exclusive generated folders and 0600 output files. No implicit scans, no original source modification and no overwrites.

## Complete resuming, triage and offline HUMAN browser usability

The actual software-only standalone.html and native browser_studio.py now
support reopening a previously saved PRIVATE HUMAN-review.csv directly
against the loaded original ledger's exact kit order and SHA-256 digests. A
strict bounded CSV parser rejects malformed quoting, unexpected rows/columns,
formulas, unrecognized HUMAN status, multiline values and changed original
kit identities BEFORE applying any edits. A previously finalized original
PRIVATE HUMAN-only.json can also be reopened into the editor only when its
ledger_sha256 exactly matches the SHA-256 of the operator-selected current
ledger.json file, all row ordinals/kit digests match and literal authority flags
are all false. Imports are HUMAN proposals and do NOT revalidate the
physical original source kit; native ledger.py finalize still reopens it.

The browser separately admits genuine HUMAN-carry.json for old-to-new
source continuity. It offers local search by kit label/ordinal/proposed owner/
next question, a HUMAN stage filter, live stage totals and visible unsaved
state. Changing source or applying a restored packet over unsaved work requires
explicit discard confirmation. Leaving a page with unexported local edits
prompts a browser warning. The original current ledger and exported HUMAN CSV
are always separate and never sent anywhere. CSV exported from the browser
still needs owner-only 0600 custody and a human native finalize;
a download request is not evidence of persistence or independent approval.

## Native source-bound HUMAN continuity between private inventory snapshots

The new [continuity.py](continuity.py) finishes the longitudinal HUMAN-only
workflow without trusting historical decisions for changed source files.

First generate a previous inventory using native capture, complete human
review, and use native finalize to create its immutable original private
HUMAN-only.json. When the same original kit paths have a fresh snapshot
created with native capture --previous, run:

    python3 assessment-workspace-ledger/continuity.py --previous /private/old-ledger/ledger.json --human /private/old-human/HUMAN-only.json --current /private/new-ledger/ledger.json --private-parent /private/private-ledgers

This original-native stage re-admits the old exact-human JSON schema and
ledger/hash/ordinal correspondence, requires the new original inventory's
previous_sha256 to equal the SHA-256 of the supplied previous ledger, and
re-opens **all CURRENT original source kit files** using the native bounded
no-follow inventory reader. It carries human stage/owner/question only where
the original and current kit's *entire* file list, file SHA-256, size, ordinal
and private kit path are literally unchanged. A changed kit automatically
starts at needs_review with empty owner/question; nothing implies clearance.
A failure of any binding aborts the entire operation before publishing.

The result is another private 0700 directory with native source-bound
HUMAN-carry.json and HUMAN-review.csv, human-only printable OPEN-PRIVATE.html
and complete RESTART-IN-BROWSER equivalent REVIEW-IN-BROWSER.html. Open the
browser, first import the **current original ledger.json**, then optionally
import **HUMAN-carry.json**. The browser requires WebCrypto SHA-256 of the
exact original JSON file bytes and compares every kit ordinal/digest before
prefilling any human rows; a bad carry leaves current decisions unchanged.
A human must reconfirm every carried choice and explicitly save a NEW CSV.
The unchanged native ledger.py finalize subsequently repeats original source
byte admission before emitting any private HUMAN-only packet. Browser notes
and statuses never create client/operator consent, security proof or PASS.

Unchanged inventories yield review-only exit 2; changed original kit bytes
lead to HOLD exit 3 even when a separate private continuity workroom is created.
The previous original HUMAN packet remains unchanged. No historical source
files are deleted, overwritten, shared or copied.

## PRIVATE original HUMAN revision journal — same source, two human packets

Native human_revisions.py provides the missing source-bound historical review
when a human has finalized different notes/stages for the SAME original ledger.
It requires two distinct original HUMAN-only.json snapshots from the native
ledger.py finalize, plus exactly their original ledger.json. It re-admits
the identical original source kit files before comparing proposals and verifies
that both native HUMAN packet source hashes/ordinals match that exact ledger.
Nothing missing, changed or unverifiable can be admitted as a valid revision.

    python3 assessment-workspace-ledger/human_revisions.py --ledger /private/ledger/ledger.json --before /private/human-old/HUMAN-only.json --after /private/human-new/HUMAN-only.json --private-parent /private/private-ledgers

A fresh 0700/0600 PRIVATE dossier contains printable source-minimal stage
change counts and per-kit HUMAN field change flags, a separate PRIVATE exact
before/after owner/question JSON, and a local HUMAN follow-up CSV. Prior
PACKETS REMAIN unchanged. Even a stage change from HOLD to reference_only
is merely a HUMAN opinion and never a completed remediation, approval,
authentication or scan authorization. Exit 2 = no differences / REVIEW_ONLY,
exit 3 = changed proposal / HOLD. The same action is console menu 8.

## Historical comparison when source kits are no longer present

The self-contained companion command compares two previously stored original
private ledger.json snapshots **without reopening the original source kits**.
It is useful for private human handoff or archival review after moving to another
trusted machine:

    python3 assessment-workspace-ledger/compare.py --before /private/ledger-before/ledger.json --after /private/ledger-after/ledger.json --private-parent /private/private-ledgers

The original slot paths and ordinal ordering must match exactly, so unrelated
packages cannot be compared as if they were revisions. It produces a fresh
owner-only 0700 package with PRIVATE-historical-comparison.json, a printable
OPEN-PRIVATE.html and a separate PRIVATE-HUMAN-comparison-template.csv.
It also produces a **separate**, owner-private PRIVATE-detail.html drilldown with
source-relative changed file names and before/after byte sizes (up to 500 rows
shown in HTML), plus the complete bounded set in PRIVATE-file-changes.json.
These sensitive detailed artifacts are never placed in the source-minimal
summary, never shared automatically, and never demonstrate verified fixes. The
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
