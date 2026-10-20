# LightUp · PRIVATE Assessment Workspace Ledger

**Incubate / M3-M7 PLAN-LAB ONLY · DRAFT/HOLD · NEVER AUTHORIZATION**

This new-only module makes already-produced private assessment workroom packages **reopenable**. A human operator can snapshot 1–12 existing owner-only packages, detect byte-level file changes before continuing HUMAN-only decisions, and compare a new snapshot to the previous one without interpreting missing evidence as a fix.

The module does not parse findings as verified, change any original producer, run tests/scans, contact targets, touch scope/grants, grant consent, send anything, or delete old packages.

## Start without assembling commands: one foreground PRIVATE operator console

The independent [console.py](console.py) is a complete guided HUMAN-only
operator interface for the exact same original native functions. Start it
locally from a trusted checkout:

    python3 assessment-workspace-ledger/console.py

Twenty-two console actions provide original kit capture, exact-byte reopen, original-bound
HUMAN CSV finalization, historical change review with private file-level
drilldown, unchanged-source HUMAN continuity, a separate source-free
single-file browser editor export, a native same-source HUMAN revision desk,
an in-memory status-only local action summary, local offline software ZIP build/inspection, and two explicit browser-download-to-private HUMAN CSV import/finalize actions. Every user-selected action runs **once, synchronously**, with no
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

## Complete local reproducible software custody and unsigned inventory

The included native package.py provides a fixed allowlist of all source-only
runtime documents/scripts and the current original standalone.html. Rebuild
a new deterministic ZIP in an existing owner-private 0700 output folder
OUTSIDE the checkout, without overwriting prior software:

    python3 assessment-workspace-ledger/package.py build --output /private/software/NEW-LightUp-Workspace-Ledger.zip

Inspect any locally saved ZIP with no network or extraction:

    python3 assessment-workspace-ledger/package.py inspect --archive /private/software/NEW-LightUp-Workspace-Ledger.zip

Build requires a trusted original checkout with the fixed source files present
as ordinary bounded regular files, and writes one exclusive mode 0600
software-only ZIP. It never reads existing customer kit directories or
operational data. Inspection rejects unsafe/unknown/reordered/duplicate ZIP
members, unsupported encodings, oversized entries, malformed or
authority-claiming manifests and any SHA256/byte-length mismatch. The bounded
software-only file hashes remain UNSIGNED, do NOT authenticate any original
author/publisher, and do not prove independent security review, consent or
permission. No scanner, active target, model, grants, network or deletion.

Both features are also foreground console options 9 and 10.

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

Original private ledger/HUMAN file reads refuse hardlinked and special (including FIFO) inputs before reading; non-blocking opens prevent a caller-supplied FIFO from suspending the offline operator workflow.\n\n## HUMAN review CSV v2 — exact original ledger identity

**Important change for all current review workflows:** HUMAN-review.csv now
has six columns, in this exact order:

    ordinal,ledger_sha256,kit_digest,stage,owner,question

Every HUMAN row binds to the SHA-256 of the entire original ledger.json file
AND the original kit digest, not merely to potentially identical kit bytes.
Native `ledger.py finalize`, `browser_intake.py`, `continuity.py` and the
offline browser now produce/accept these exact source-bound v2 rows. This
prevents applying a review to a different case ledger sharing identical kit
contents. Source identity is an UNSIGNED byte-level consistency relation,
never source-owner authentication, consent, or security clearance.

**Legacy migration:** Five-column v1 HUMAN-review.csv from the earlier
held software will be rejected by native finalize/import rather than
silently treated as current case context. To recover the old HUMAN decisions,
open the new standalone.html locally, select the ORIGINAL current ledger.json
and then import the old HUMAN-review.csv. The browser warns that the old
review is UNBOUND to the complete ledger, requires explicit human confirmation
before importing as an UNTRUSTED draft, and requires a manual review of every
proposed stage/owner/question. Export a NEW six-column source-bound CSV,
then perform the normal PRIVATE ingress/finalization procedure. The legacy
draft is NOT automatically approved or independently source-proven. If the
offline browser cannot compute the ledger SHA-256, v2 export fails closed.

## Owner-private ingress from a browser Downloads HUMAN-review.csv

Browsers normally save the HUMAN-review.csv into Downloads using local
filesystem defaults; it may be readable by other users and intentionally
fails the native 0600 PRIVATE finalizer. The new browser_intake.py explicitly
accepts ONLY an explicitly selected HUMAN-review.csv (including browser-renamed
HUMAN-review (1).csv / HUMAN-review(1).csv variants), does not follow its
final symlink, requires owner-owned ordinary single-link regular <=64KiB
source, and reads stable original bytes before parsing all source-bound HUMAN
rows and exact current source-kit hashes. Its private output is a NEW
exclusive 0700 directory containing 0600 unchanged HUMAN-review.csv and an
offline custody note. Original Downloads file stays untouched, un-chmodded,
undeleted and may remain visible to other local users: the importer DOES NOT
retroactively make the original download private. The operator should review
and privately dispose of the old browser copy according to their own policy.

    python3 assessment-workspace-ledger/browser_intake.py --ledger /private/original-ledger/ledger.json --csv /home/operator/Downloads/HUMAN-review.csv --private-parent /private/owner-private

To complete the next native step as one explicit foreground action, add
--finalize. The importer then delegates to UNCHANGED native ledger.finalize()
against the newly staged owner-private CSV. That finalizer independently
re-reads the exact original kit source files and emits a separate HOLD-only
human packet; no verification, customer grant or security approval is inferred.
Return code 2 means REVIEW_ONLY import without finalization; --finalize
always remains HOLD 3, even after preparing a PRIVATE HUMAN packet.

Foreground console actions 11 and 12 run these two variants. No network,
shell, scanning, privileged filesystem changes or browser automation.

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

## Original file read privacy rechecked at the actual descriptor

The original kit inventory now rechecks **actual opened** descriptor owner UID,
group/other mode bits, exact single-link identity, size, mtime and ctime against
the earlier no-follow directory-entry metadata **before hashing any file
bytes**. A metadata or permission change between directory traversal and file
open therefore causes PRIVATE HOLD, not silent acceptance. The existing
post-read descriptor change check still applies. This is a local byte/privacy
admission invariant, never producer authentication or customer consent.

## Human dossier context changes are first-class HOLD

Source kit equality is not merely equal file bytes. The original HUMAN
label describes which dossier a human operator is reviewing. During
`ledger.py capture --previous`, a changed original kit label forces HOLD
and appears explicitly in the private local summary even if all source
files and their SHA-256 values are identical. `continuity.py` also drops
ALL previously carried HUMAN stage, owner and question fields on such a
label change. `compare.py` records a separate label_changed indicator,
marks HUMAN attention required, and includes the flag in the private
historical follow-up CSV. Original kit path, ordinal and exact source bytes
must still match for any unchanged-source continuation.

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


## Chained PRIVATE inventory history — 2–12 original snapshots

The new [history.py](history.py) and foreground console action **13** create a
single human-readable history from an explicitly selected ordered series of
original **owner-private ledger.json** files, without reopening customer kit
contents or sending anything to a server. Each entry after the first MUST have
been generated using the original `ledger.py capture --previous` pointing to
exactly the preceding ledger bytes. Native admission requires its exact
`previous_sha256` to match, all original kit paths/ordinals to remain fixed,
private ordinary files, distinct exact bytes, bounded original JSON and all
literal non-authority fields. A missing, reordered or mismatched historical
source produces HOLD; **the chain is unsigned and its chronology is not
cryptographically proven**.

    python3 assessment-workspace-ledger/history.py --ledger /private/one/ledger.json --ledger /private/two/ledger.json --ledger /private/three/ledger.json --private-parent /private/private-ledgers

The tool creates an exclusive owner-only 0700 workroom with 0600
`OPEN-PRIVATE.html` (local source-minimal per-kit/per-step change table),
`PRIVATE-history.json` (bounded multi-step counters),
`PRIVATE-relative-file-hotspots.json` (sensitive original relative filenames
and file-churn frequency), separate scriptless `PRIVATE-hotspots.html` with
up to 500 HTML-escaped highest-churn original relative path records and a
link back to the source-minimal overview, and `PRIVATE-HUMAN-history-template.csv`
(numeric HUMAN-only action worksheet). The full bounded original path history
remains in owner-private JSON, not a public anonymous export. A historical
review workroom is never created inside any original source kit directory. Every step distinguishes label/context drift
from added, removed or changed original file bytes. Even a zero-change step
is merely **REVIEW_ONLY**, and any drift returns **HOLD**. A missing historical
source file never implies a fixed issue. These inventories say NOTHING about
actual current source bytes until the latest ledger is separately admitted
using the original `ledger.py reopen` command. No scan, live target,
sharing, owner-authentication, real consent, grant or verified finding.

The fixed allowlist source-only ZIP packaging schema is now v11 and includes
this timeline CLI. A prior committed v10 ZIP remains a **previous software
revision**, not a representation of these new committed sources: build a new
software-only ZIP with `package.py build` from the current source tree.


## NEW v12: complete OFFLINE historical HUMAN review and local browser custody

The earlier history feature now has an interactive operator workflow, without
reopening original kit data, granting assessment authority or requiring a
web server. Open the owner-private \`REVIEW-HISTORY-IN-BROWSER.html\` generated
alongside \`OPEN-PRIVATE.html\` by history.py. The self-contained browser uses
a CSP SHA-256 pin, no remote resources, no fetch or browser storage. It carries
only source-minimal original private kit labels, numeric changes, unsigned
per-kit file-list SHA-256 and the exact ORIGINAL ledger SHA-256 chain. Keep
this generated PRIVATE HTML under 0700/0600 custody.

The editor shows every original transition/kit, filters by HUMAN status,
supports local search, and allows HUMAN-only stage/owner/next-question
proposals. It can reopen an exactly matching previously exported
\`HUMAN-history-review.csv\`; it rejects missing/reordered/mismatched original
ledger/kit SHA-256, unexpected fields/rows/quoting, formula-prefixed text,
oversized or multiline values. A draft resume requires confirmation before
discarding unsaved local HUMAN entries. Nothing is published or scanned by
the browser. An export creates \`HUMAN-history-review.csv\` in the browser's
normal Downloads area, potentially readable by other local users.

Native [history_human.py](history_human.py) **must** be run separately to
finalize the HUMAN packet. It reopens the exact 2–12 ORIGINAL archived private
ledger.json files in the same order, admits the original full-ledger
\`capture --previous\` SHA-256 links, verifies every CSV transition's
original source-ledger SHA-256, kit file-list digest, immutable numeric counts,
dossier-label drift, HUMAN status and bounded safe text. The exact original
ledger bytes are opened AGAIN immediately before private publication.
No current customer source files are reopened by historical-finalize; use the
original \`ledger.py reopen\` separately for a new live source-byte check.

**Private 0600 CSV already staged:**

    python3 assessment-workspace-ledger/history_human.py --ledger /private/one/ledger.json --ledger /private/two/ledger.json --plan /private/staged/HUMAN-history-review.csv --private-parent /private/private-ledgers

**Explicit original browser-downloaded CSV, with source file left unchanged:**

    python3 assessment-workspace-ledger/history_human.py --ledger /private/one/ledger.json --ledger /private/two/ledger.json --browser-csv /home/operator/Downloads/HUMAN-history-review.csv --private-parent /private/private-ledgers

Repeat \`--ledger\` for every additional capture-linked original in exact
HUMAN-selected order. Console options **14** and **15** guide the same native
private-plan or browser-downloaded workflow. Strict original browser CSV
admission refuses symlinks, hardlinks, nonregular input, another user's files,
and changed/oversized bytes, then publishes a *new* 0700/0600 original-bound
PRIVATE packet with \`PRIVATE-HUMAN-history.json\`,
\`PRIVATE-HUMAN-history.html\`, a fresh PRIVATE copy of
\`HUMAN-history-review.csv\`, and \`OPEN-PRIVATE.html\`. The ORIGINAL browser
file is never chmodded, overwritten, moved or deleted; prior exposure cannot
be reversed. Returned status remains **HOLD 3**, including HUMAN stages
labelled reference_only.

Older v11 historical numeric-only review templates cannot pass v12's new
native importer because v12 binds every review row to exact source ledger
SHA-256 and original per-kit digest. Regenerate the new template or export
from its private browser. The previous committed v11 software ZIP is an old
source-only revision; the v12 source-only ZIP now includes the actual native
historical HUMAN finalizer and CSP-pinned browser renderer. No new QA/tests,
authorization, client handling, verified security claim, network, active
scan, external publication or deployment was added.


## NEW v13: complete PRIVATE two-to-eight HUMAN reviewer conflict desk

When 2–8 humans have independently completed ORIGINAL native
`PRIVATE-HUMAN-history.json` packets against precisely the same **2–12**
original source-ledger snapshots, [history_team.py](history_team.py) opens
all explicitly chosen archived ledgers/packets and refuses changed,
duplicate, inconsistent or misordered original full-ledger SHA identities.
It also re-admits **every original per-step/per-kit digest and literal file
change count**, original HUMAN status/owner/question bounds, and six literal
no-authority flags. These packets have **UNSIGNED** hashes; matching opinions
do **not** establish actual human identity or independent trust.

**Prepare an actual owner-private HUMAN coordination workroom:**

    python3 assessment-workspace-ledger/history_team.py prepare --ledger /private/one/ledger.json --ledger /private/two/ledger.json --reviewer /private/team-A/PRIVATE-HUMAN-history.json --reviewer /private/team-B/PRIVATE-HUMAN-history.json --private-parent /private/private-ledgers

Repeat `--ledger` for each originally chained source snapshot and
`--reviewer` for 2–8 distinct original native HUMAN history packets.
A NEW 0700 workroom with 0600 `PRIVATE-team-context.json`,
`OPEN-PRIVATE.html`, `HUMAN-team-review-template.csv`, and
`REVIEW-TEAM-IN-BROWSER.html` is created without modifying old packets.
The overview shows only numeric counts of HUMAN disagreement/identical
opinions; the separate offline CSP-hash-pinned review browser contains
PRIVATE HUMAN owners/questions and unsigned source fingerprints. It must
**not** be shared or served publicly.

The complete [history_team_browser.py](history_team_browser.py) native renderer
shows reviewers side by side per original kit/transition, highlights HUMAN
opinion disagreement, supports local search and filtering, explicit
reviewer selection per item, and all-NONE by default. There is an explicit
human-confirmed convenience action to select reviewer 1 **only when HUMAN
opinions match**; it does not constitute approval. Exact-original CSV drafts
can be reloaded without changing local edits on a failed admission; leaving
with unsaved selections warns. Browser export creates a local
`HUMAN-team-review.csv` in Downloads, potentially accessible by other
local users. No network, HTML import, local storage, grant or scan.

**Native source-bound finalization from an owner-private 0600 CSV:**

    python3 assessment-workspace-ledger/history_team.py finalize --context /private/new-team-room/PRIVATE-team-context.json --csv /private/private/HUMAN-team-review.csv --private-parent /private/private-ledgers

**Or explicitly ingest the original browser download without chmod, renaming,
or deleting it:**

    python3 assessment-workspace-ledger/history_team.py finalize --context /private/new-team-room/PRIVATE-team-context.json --browser-csv /home/operator/Downloads/HUMAN-team-review.csv --private-parent /private/private-ledgers

The native finalizer re-opens the **EXACT original archived private source-ledger
bytes and all original native HUMAN packet bytes**, validates their recorded
SHA-256 against the stored owner-private context (including rechecking before
publication), and admits one CSV choice per original transition/kit. Every
selected status, HUMAN owner and HUMAN question must literally match the
original unchanged selected packet SHA-256 for that exact row. NONE is always
needs_review with empty owner/question. Unknown/spliced/reordered source,
stale reviewer packet, altered fields, unknown CSV columns or formula-like
original HUMAN inputs cause HOLD. There is no automatic decision from
matching reviewer opinions and no arbitrary synthesis of reviewer statements.

The NEW owner-only 0700/0600 output has `PRIVATE-HUMAN-team-choice.json`,
`PRIVATE-HUMAN-team-choice.html`, `HUMAN-team-review.csv` and
`OPEN-PRIVATE.html`. This is a PRIVATE HUMAN selection ledger only. It does
not authenticate individual reviewers, check current original kit files,
validate a vulnerability, approve remediation, grant scope/consent or authorize
live work. For current physical kit-byte admission use the unchanged original
`ledger.py reopen` explicitly and separately. The native operation ALWAYS
returns **HOLD 3**. Console actions **16, 17 and 18** expose preparation,
PRIVATE owner-only CSV finalization, and browser-download custody.

**Software distribution:** source-only manifest schema v13 adds
`history_team.py` and `history_team_browser.py` to the existing exact
portable offline ZIP allowlist. The shipped ZIP includes no original HUMAN
packet, source ledger, actual client material, browser-generated private
review HTML or real human workroom. Do not treat a software byte digest as
publisher authentication, a security gate, verified consent or HUMAN GO.


## Native exact-literal authorization integrity across historical inputs

The original ledger, finalized native HUMAN continuity packet and offline
software package inspector now share a strict authority-value reader: each
expected no-permission claim must be the **actual JSON boolean false** and
all original fixed authority field names must match exactly. JSON numeric
`0` is never an alias for `false`. An integer-equivalent or missing flag
is HOLD before any original private source or HUMAN interpretation proceeds.
The new multi-reviewer native packet/context reader separately enforces the
same exact JSON literal requirement. This is an offline record-integrity
admission fix, never evidence of actual authorization, independent review,
correctness of an original source producer or a security release.

 
## NEW v14 — complete offline PRIVATE HUMAN follow-up action board

The source-exact original HUMAN reviewer selection now has a real next step.
[history_actions.py](history_actions.py) opens the **ORIGINAL** native team
context, original finalized PRIVATE HUMAN team choices **and their original
native HUMAN-team-review.csv**, not copied claims from an unreviewed document.
It reopens all linked original stored ledger files and all 2–8 native original
HUMAN reviewer packets using the unchanged native admission code. Every
selected team decision must match an actual unchanged source-bound original
packet and the archived original review CSV. It rejects unknown native source
records, changed archived bytes, forged team choice rows, numeric permission
flags, noncanonical file paths and duplicate JSON keys. The workflow does
**NOT** reopen current customer kit contents; it is an *historical manual
planning aid*, not a completed assessment or true authenticated ownership.

**1. Make a new owner-private offline planning workspace:**

    python3 assessment-workspace-ledger/history_actions.py prepare --context /private/team-workroom/PRIVATE-team-context.json --team-choice /private/team-result/PRIVATE-HUMAN-team-choice.json --team-csv /private/team-result/HUMAN-team-review.csv --private-parent /private/private-ledgers

A **new** 0700/0600 workroom contains a native identity-bound initial
`HUMAN-action-plan-template.csv`, `PRIVATE-action-context.json`,
`OPEN-PRIVATE.html` and an actually rendered
`REVIEW-ACTIONS-IN-BROWSER.html`. The CSP-SHA256-pinned standalone browser
has no network, fetch, storage, external libraries or background workers.
It shows the original archived HUMAN review question and stage per source
kit/transition (never an authenticated finding), supports manual case search,
status filtering, draft-only suggested HUMAN work priority, accountable human,
optional proposed day and next HUMAN step, a protected unsaved edit warning,
and safe exact-original CSV draft resume. No action is assigned automatically.
Every action defaults to `unassigned`. A HUMAN proposal requires an explicit
accountable human and next step. A proposed day is optional, an unbooked HUMAN
date **not** a real calendar meeting, deadline or schedule.

Browser-local download `HUMAN-action-plan.csv` may be public-readable in
Downloads. Keep it owner-private if possible, or use the original explicit
browser admission route below. Do not send source paths or personal text via
email/Notion/GitHub.

**2. Explicitly finalize an existing owner-only PRIVATE CSV:**

    python3 assessment-workspace-ledger/history_actions.py finalize --action-context /private/new-action-room/PRIVATE-action-context.json --plan /private/HUMAN-action-plan.csv --private-parent /private/private-ledgers

**Alternatively import a user-selected original browser download:**

    python3 assessment-workspace-ledger/history_actions.py finalize --action-context /private/new-action-room/PRIVATE-action-context.json --browser-csv /home/operator/Downloads/HUMAN-action-plan.csv --private-parent /private/private-ledgers

On finalization the native tool reopens the ORIGINAL ledger files, reviewer
packets, team choice JSON and HUMAN team CSV, verifies their exact SHA256
against the initial owner-private context **again before writing**, then
admits only native action fields bound to exact original ledger/kit/reviewer
SHA and immutable HUMAN stage. Unassigned status cannot pretend to have an
owner, priority, day or task. Proposed HUMAN action needs both a specific
accountable HUMAN and an explicit manual next step. It rejects invalid
dates, unknown values, nonliteral original authority, formula-prefixed text,
multiline notes, hardlinks/symlinks or mutated downloads.

The result is a NEW 0700 directory with exclusive 0600
`PRIVATE-HUMAN-actions.json`, `PRIVATE-HUMAN-actions.html`,
`HUMAN-action-plan.csv` and source-minimal `OPEN-PRIVATE.html`.
**Every result is PRIVATE HOLD (3), never a dispatched task, schedule,
grant, client approval, verified security finding or remediation proof.**
The selected original browser file is unchanged; prior potential
exposure is not reversed.

Original foreground console options **19–21** guide the same complete
HUMAN-only workflow. Fixed source-only ZIP manifest v14 includes actual native
history_actions.py and history_actions_browser.py. The ZIP contains NO
human data, customer material, generated private HTML, client kit, consent
or active-target software invocation. It is not a security-reviewed release
or live operator authorization. No QA/test suites were authored or run.

 
## NEW v15 — minimum-necessary owner-specific PRIVATE HUMAN handoff

The complete offline action plan may include PRIVATE human questions and
names belonging to different team members. The new native
[history_owner_brief.py](history_owner_brief.py) prepares a deliberately
selected **single-human** brief without disclosing other owners' proposed
work or PRIVATE questions. This is not a transport or recipient-authentication
service: it never mails, uploads, publishes, assigns or dispatches a task.

The operator selects the ORIGINAL native `PRIVATE-action-context.json`,
the ORIGINAL native completed `PRIVATE-HUMAN-actions.json`, and its exact
source-bound owner-private `HUMAN-action-plan.csv`. The native reader
reopens the underlying exact ORIGINAL archived ledger chain and original
HUMAN reviewer packets and checks the finalized team choice and action CSV
using the original strict native admission code. Every row must be from
the actual unchanged source-bound original human plan. Unknown or changed
originals fail without output. This is NOT current physical kit-file
revalidation; original kits still require a separate `ledger.py reopen`.
The owner label is just a local human string, not verified identity or
distribution consent.

    python3 assessment-workspace-ledger/history_owner_brief.py --action-context /private/actions/PRIVATE-action-context.json --actions /private/final-actions/PRIVATE-HUMAN-actions.json --plan /private/final-actions/HUMAN-action-plan.csv --owner "EXACT local proposed HUMAN" --private-parent /private/private-ledgers

The command refuses an unknown/empty owner, mismatching original source,
legacy malformed or noncanonical authority fields and original actions with
no explicit HUMAN work. It reopens all the same native originals once more
before publication and creates a NEW 0700/0600 private package containing
`PRIVATE-HUMAN-owner-brief.json`, printable
`PRIVATE-HUMAN-owner-brief.html` and `OPEN-PRIVATE.html`. These contain
**only the manually selected owner's** proposals, source ordinal, proposed
priority/day and next manual action. No original customer source paths,
other owners' HUMAN questions, automatic work acceptance, security-grade
severity, verified remediation, active target, scope authority or
authenticated recipient is included. All output remains HUMAN-only HOLD (3).

Native foreground console option **22** guides this entire minimum-necessary
owner handoff. Fixed v15 software-only ZIP packaging includes the real
native owner-brief CLI; it never bundles generated private workrooms.
Any actual disclosure still needs independent verified recipient identity,
client consent and applicable privacy/security authorization. No QA
or test suites created or run and no live scan or deploy.
