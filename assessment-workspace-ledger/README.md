# LightUp · PRIVATE Assessment Workspace Ledger

**Incubate / M3-M7 PLAN-LAB ONLY · DRAFT/HOLD · NEVER AUTHORIZATION**

This new-only module makes already-produced private assessment workroom packages **reopenable**. A human operator can snapshot 1–12 existing owner-only packages, detect byte-level file changes before continuing HUMAN-only decisions, and compare a new snapshot to the previous one without interpreting missing evidence as a fix.

The module does not parse findings as verified, change any original producer, run tests/scans, contact targets, touch scope/grants, grant consent, send anything, or delete old packages.

## Start without assembling commands: one foreground PRIVATE operator console

The independent [console.py](console.py) is a complete guided HUMAN-only
operator interface for the exact same original native functions. Start it
locally from a trusted checkout:

    python3 assessment-workspace-ledger/console.py

Twenty-seven console actions provide original kit capture, exact-byte reopen, original-bound
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

 
## NEW v16 — exact-original HUMAN follow-up progress and PRIVATE worklist

Native [history_progress.py](history_progress.py) is a complete offline
HUMAN-only review desk for **2–8 originally finalized PRIVATE action
snapshots**. Unlike comparing loose CSV files, it reopens every original
native `PRIVATE-HUMAN-actions.json`, that packet's exact
`HUMAN-action-plan.csv` and the SAME separately selected ORIGINAL
`PRIVATE-action-context.json`. Existing `history_owner_brief.admitted_original`
in turn readmits ALL ORIGINAL 2–12 archived ledger snapshots, the native
source-bound reviewer packets and finalized team human choices. Any changed
original or packet, duplicate revision, changed original chain/row identity,
unknown source record, or nonnative HUMAN CSV makes the full review HOLD.
Original actual customer kit bytes remain unopened: this is a HUMAN proposal
history, not active security evidence or source-authenticated chronology.

**Choose revisions in deliberate HUMAN order, paired JSON and CSV:**

    python3 assessment-workspace-ledger/history_progress.py --action-context /private/original-action-room/PRIVATE-action-context.json --actions /private/version-A/PRIVATE-HUMAN-actions.json --plan /private/version-A/HUMAN-action-plan.csv --actions /private/version-B/PRIVATE-HUMAN-actions.json --plan /private/version-B/HUMAN-action-plan.csv --private-parent /private/private-ledgers

Repeat each `--actions` and matching `--plan` pair for up to 8
different original source-bound snapshots; **all must belong to precisely
the same original HUMAN source context**, and all snapshots must be in
the operator's requested comparison order. No timestamps or signed
chronology are fabricated. Native console option **23** guides the process.

The tool produces a NEW 0700/0600 owner-private workroom with five finished
outputs:

- `OPEN-PRIVATE.html`: source-minimal summary of changed HUMAN proposal
  counts, status totals and changed fields for each operator-ordered step,
  without human names, next-step PRIVATE text or SHA paths.
- `PRIVATE-HUMAN-changes.html`: fully HTML-escaped per-field details
  of changed HUMAN action state, priority, proposed owner, suggested day
  and next human step, with previous and new values.
- `PRIVATE-HUMAN-worklist.html`: the latest *human-selected* original
  proposed work, sorted by suggested day (undated last), HUMAN priority,
  owner and original kit; source-relative customer paths omitted.
- `PRIVATE-HUMAN-changes.csv`: limited-necessary original kit identifiers,
  change flags, old/new status, proposed owner/day and HUMAN priority,
  without source/customer file content or free-text HUMAN questions.
- `PRIVATE-HUMAN-progress.json`: complete owner-private original-bound
  source ledger/packet SHA inventory, HUMAN-change history and latest worklist.

This never opens current customer kit bytes, does not contact assets or
network resources and NEVER proves a remediation, vulnerability, authentic
reviewer, calendar deadline, approved work, grant, consent or owner
authorization. Status and days are *historical HUMAN proposals* and all
outputs remain PRIVATE HOLD (3). The private output is never a public
portfolio report or live operations task queue. Use the native
`ledger.py reopen` separately before a genuine new source-byte decision.
No QA, regression or testing suite is added. The fixed v16 source-only
software ZIP adds the original history_progress.py implementation, but
no customer/PRIVATE source content or generated workroom.


## PRIVATE cross-case HUMAN portfolio · independent original cases (console 24)

The native [portfolio.py](portfolio.py) assembles **2–8 distinct**, originally
finalized owner-private historical HUMAN action cases into one practical
offline follow-up dashboard. Each case must have its own complete original
`PRIVATE-action-context.json`, `PRIVATE-HUMAN-actions.json`, and matching
`HUMAN-action-plan.csv`. These are **three corresponding original files per
case**, not interchangeable exports. Original native source-chain admission
runs for each case separately; duplicate case contexts, mismatched source
records and malformed/changed inputs fail closed. It does not reinterpret
different-case proposals as a single actual security finding.

Run from a trusted local checkout (repeat each option once per case):

    python3 assessment-workspace-ledger/portfolio.py \
      --context /private/case-A/PRIVATE-action-context.json \
      --actions /private/case-A/PRIVATE-HUMAN-actions.json \
      --plan /private/case-A/HUMAN-action-plan.csv \
      --context /private/case-B/PRIVATE-action-context.json \
      --actions /private/case-B/PRIVATE-HUMAN-actions.json \
      --plan /private/case-B/HUMAN-action-plan.csv \
      --private-parent /private/portfolio-output

Console option **24** offers the same guided workflow with no shell or automatic
action. The destination must already be a private owner-only 0700 directory
outside the checkout and outside every original source kit. Private source
files remain untouched; original chain admission is repeated before any new
output is written.

A **new** exclusive 0700 folder contains:
- `OPEN-PRIVATE.html`: source-minimal per-case status and proposal counts,
  without original hashes, personal names or next-step text.
- `PRIVATE-HUMAN-portfolio.html`: sensitive, HTML-escaped local worklist
  sorted by manually proposed day/priority with **case ordinal preserved**.
- `PRIVATE-HUMAN-portfolio.csv`: human-only proposed steps, explicitly bound
  to each case context SHA and its original action-packet SHA.
- `PRIVATE-HUMAN-portfolio.json`: private canonical original-byte-bound
  source identities, local status counts and suggested HUMAN steps.

All output files use 0600 permissions; the operator console and CLI always
return **HOLD (3)**. These are historic, unsigned human suggestions, not
executed work, authenticated recipients, deadlines, independent evidence,
verified vulnerabilities, release clearance, source re-opening, consent,
authorization, scan output, dispatch, or remediation. Do not share original
customer data or these PRIVATE files without a separate authorized disclosure
process. The **source checkout** includes `portfolio.py`; the native
`package.py build` now produces a complete v19 offline software ZIP with
this module included, using only installed original trusted software bytes.
The branch's [published source-only v19 offline ZIP](LightUp-Workspace-Ledger-Offline.zip)
contains all original and newly added software files, including both portfolio
modules. It is an **UNSIGNED** offline toolkit: source hashes are byte
identities, not software publisher authentication, security review or permission.
The native inspector retains read-only compatibility with prior v16/v17
archive layouts; those historical layouts are not the current branch download.
The v19 software package contains no original customer data.

For minimum-necessary casework, specify an optional exact proposed owner:

    python3 assessment-workspace-ledger/portfolio.py \
      --context /private/case-A/PRIVATE-action-context.json \
      --actions /private/case-A/PRIVATE-HUMAN-actions.json \
      --plan /private/case-A/HUMAN-action-plan.csv \
      --context /private/case-B/PRIVATE-action-context.json \
      --actions /private/case-B/PRIVATE-HUMAN-actions.json \
      --plan /private/case-B/HUMAN-action-plan.csv \
      --owner "LOCAL PROPOSED HUMAN OWNER" \
      --private-parent /private/portfolio-output

Owner filtering excludes all other owners' proposed actions and their
source-context identifiers from the filtered portfolio output. The
source-chain admission still covers every explicitly selected original
case before private export. An owner string is **not authenticated identity**
or disclosure consent. Only exact matching manual proposals appear; zero
matches is HOLD. Console option 24 supports the same optional filter.
No QA/regression/test suite is created or executed.

## PRIVATE original cross-case HUMAN portfolio changes (console 25)

The independent native [portfolio_delta.py](portfolio_delta.py) performs a
**historical HUMAN change review** between two existing original
`PRIVATE-HUMAN-portfolio.json` records created by the native cross-case
portfolio workflow above, after their corresponding ORIGINAL completed
HUMAN actions have been re-admitted separately on capture.

    python3 assessment-workspace-ledger/portfolio_delta.py \
      --before /private/portfolio-previous/PRIVATE-HUMAN-portfolio.json \
      --after /private/portfolio-current/PRIVATE-HUMAN-portfolio.json \
      --private-parent /private/portfolio-delta-output

Console **option 25** guides the same workflow. It requires that both
originals have matching original **case ordinals and source-context SHA-256s**
and the same filtered/unfiltered HUMAN-owner scope. It reads only the
pre-existing 0600 local historical snapshots (bounded 1 MiB, single-link,
owner-only), rejects duplicate and malformed JSON keys, wrong canonical byte
representation, contradictory original HUMAN case status counts and changed
source identities. Each ordinal/transition/kit HUMAN action remains distinct;
owners, HUMAN stages, suggested dates and free-text follow-ups are NEVER
interpreted as actual activities.

**New owner-private output:** a source-minimal `OPEN-PRIVATE.html` shows
counts of HUMAN proposals added, removed, edited, and unchanged. A separate
`PRIVATE-HUMAN-delta.html` contains detailed escaped old/new HUMAN suggestions;
`PRIVATE-HUMAN-delta.csv` and `PRIVATE-HUMAN-delta.json` preserve the
unsigned source-record hashes and before/after fields for offline review.

The action-context SHA match is only **unsigned, historical consistency**.
The original customer kits are NOT reopened, real consent is NOT revalidated,
and a removed proposal is NEVER proof that a vulnerability was fixed.
Neither output auto-dispatches actions, launches assessments, creates deadlines
or authenticates the proposed human recipient. Privacy depends on explicit
operator control of owner-only outputs. The committed current v19 offline source-only ZIP includes both portfolio
modules and the original complete software. SHA-256 hashes authenticate only
local byte equality, NOT the publisher or an approved real security action.
No QA/regression/test suites are created or run.


## New: source-bound PRIVATE HUMAN owner packet handoff (console 26)

The native [portfolio_owner_packets.py](portfolio_owner_packets.py) is a
separate **offline minimum-necessary recipient workroom builder** for an
existing original private cross-case `PRIVATE-HUMAN-portfolio.json`.

    python3 assessment-workspace-ledger/portfolio_owner_packets.py \
      --portfolio /private/original/PRIVATE-HUMAN-portfolio.json \
      --owner "EXACT PROPOSED HUMAN OWNER A" \
      --owner "EXACT PROPOSED HUMAN OWNER B" \
      --private-parent /private/local-workrooms

The operator must explicitly choose **1–8 distinct exact proposed-human
labels**; there is no "send everyone", automatic recipient discovery,
email, cloud integration or silent distribution. Owner labels, plans and
reviewer decisions remain **UNAUTHENTICATED HUMAN claims**, not actual
client consent, legal permission, confirmed assignments or approved work.

The original source file is admitted through the strict native v1 portfolio
schema reader with owner-owned 0600, no-follow, single-link, bounded byte
reads, literal all-false authority, canonical JSON, original context hashes
and internally matching original action-packet identities. The exact stored
source bytes are re-read before generating private output. Missing owner,
duplicated owner, altered source or a request to broaden an already
owner-filtered portfolio fails closed.

A **new** exclusive owner-private 0700 directory contains one minimal local
index showing only anonymous owner ordinals and suggested-action counts.
Each deliberately selected owner gets its own dedicated 0700 subdirectory,
0600 escaped HTML workroom, 0600 HUMAN-only CSV and 0600 original-portfolio
SHA/source-case-exact private JSON; **other owners' names, action text and
case hashes are excluded from that owner's files**. The local index does not
display owner names, source hashes, case paths, targets or action text.
All source content stays on the operator's machine; the originals are not
modified, moved, uploaded, deleted, rescanned or reauthorized.

The return state is always **PRIVATE HOLD (3)**. The code performs no
disclosure, encryption, authentication, digital signature, network request,
scan, security remediation, task dispatch, booking or notification. Private
0600 filesystem permissions are not encryption. Before a human operator
separately shares anything, real recipient identity and specific disclosure
authority must be authenticated outside this offline workroom.

The committed v19 package contains 22 original and additive software files,
including `portfolio_owner_packets.py`; older v16/v17/v18 layouts remain
recognizable *only* as historical unsigned software packages during
read-only inspection. GitHub's packaged ZIP must be identified by its
actual current commit and manifest; no previous release becomes authorized.
No QA, regression or test suite has been created or executed.

### Historical per-owner case visibility (source-context guard)

The original v1 HUMAN portfolio deliberately omits unselected case identities
from an owner-filtered workroom. As a consequence, when a new human proposal
appears or disappears for that owner, that **case slot** may appear or
vanish. The native `portfolio_delta.py` now reports newly/no-longer visible
owner-filtered case slots as HUMAN proposal membership changes, **only if
at least one shared original case context SHA and ordinal anchors the two
portfolios**. All common original case identities must match; two unrelated
collections with no shared case are rejected. Full, unfiltered portfolio
comparison still demands exactly identical source-case rosters. No removed
HUMAN proposal, slot or worklist row is evidence of a fixed vulnerability,
revoked grant, completed action or successful retest.

## PRIVATE cross-case HUMAN date/priority planning dayboard · console 27

The native [portfolio_dayboard.py](portfolio_dayboard.py) opens an existing
original owner-private, source-bound `PRIVATE-HUMAN-portfolio.json` from the
prior cross-case workflow. It creates a *new* isolated source-bound HUMAN
planning view grouped by the **explicitly selected reference day**, manually
proposed HUMAN priority, status and proposed owner.

    python3 assessment-workspace-ledger/portfolio_dayboard.py \
      --portfolio /private/portfolio/PRIVATE-HUMAN-portfolio.json \
      --reference-day 2026-10-20 \
      --private-parent /private/dayboards

To restrict the PRIVATE output to one original proposed HUMAN label, add:

    --owner "EXACT PROPOSED HUMAN OWNER LABEL"

**There is no implicit local/system date and no real deadline claim.** The
HUMAN must choose the comparison date. Each original proposed day is grouped
into `past_proposed_day`, `selected_reference_day`,
`later_proposed_day` or `no_proposed_day`; these are **historical HUMAN
proposal-relative buckets**, never proof of actual overdue assignments or
appointments. Existing owner-filtered original portfolios cannot be
expanded: omitting `--owner` on such an input automatically preserves the
original exact HUMAN-owner scope and does not reveal other owners.

The native source reader re-admits the original canonical 0600 owner-only
source record, checks unsigned exact original case identities and all-false
authority, and reads the unchanged original a second time before producing
anything. It neither accesses original customer kits nor any target/network.

New 0700 output folder and strictly owner-private 0600 files:
- `OPEN-PRIVATE.html`: counts by historical HUMAN date bucket and priority
  with NO owner names, action text, case hashes or target identities.
- `PRIVATE-HUMAN-dayboard.html`: fully escaped PRIVATE workboard with proposed
  day, priority, original case/transition/kit, original HUMAN status,
  proposed owner and next step.
- `PRIVATE-HUMAN-dayboard.csv`: source-relative HUMAN worklist, for PRIVATE
  offline review only.
- `PRIVATE-HUMAN-owner-capacity.csv`: detailed **PRIVATE** per-proposed-owner
  suggestion counts for dates/priorities. These do NOT authenticate real
  assignments or reveal an actual person's workload.
- `PRIVATE-HUMAN-dayboard.json`: original source-portfolio SHA, the explicitly
  chosen date, exact original visible case SHA identities, literal no-authority
  flags and the HUMAN-only proposals/aggregates, all <= native 1 MiB limit.

Console **option 27** provides the same guided single foreground run with
manual date and optional exact owner. Nothing is queued, transmitted,
scheduled, signed, approved or independently verified; exit remains HOLD (3).
Neither source SHA nor unsigned planner stages constitute client/operator
consent, scope approval, a completed finding, a fix, authentic recipients or
permission to share PRIVATE work. The source-only v20 software bundle adds
`portfolio_dayboard.py`, preserving read-only historical package support
for v16/v17/v18/v19; no QA/regression/test suites were created or run.

## Source-bound PRIVATE HUMAN focus meeting · software v21

The original [portfolio_focus.py](portfolio_focus.py) uses the already-created
2–8-case owner-private HUMAN portfolio, not original assessment-kit data. It
creates a minimum-necessary **HUMAN follow-up meeting packet** after the
operator explicitly selects historical day buckets, priorities and optionally
the exact proposed HUMAN owner (a label, never recipient authentication).

    python3 assessment-workspace-ledger/portfolio_focus.py \
      --portfolio /private/source/PRIVATE-HUMAN-portfolio.json \
      --reference-day 2026-10-20 --title "Historical HUMAN review" \
      --priority human_urgent --priority near_term \
      --bucket past_proposed_day --bucket selected_reference_day \
      --private-parent /private/owner-only

Outputs in one exclusive 0700 private directory: source-minimal summary HTML,
scriptless PRIVATE detailed meeting HTML, private Markdown and CSV, and
source-portfolio-SHA-bound JSON. The original strict portfolio admission runs
before output and immediately re-admits original bytes; owner-filtered input
can never widen into another owner. Empty or malformed selection fails closed.
Console option 28 provides the same foreground function.

These historical suggestions are **not** deadlines, actual tasks, authorized
recipients, real consent, verified remediation, scan permission, booking or
HUMAN GO. No external communication, scheduling, network, worker, background
task or original security scan is performed. The software-only ZIP v21 includes
this module and continues inspecting legacy fixed v16–v20 software inventories.

## Source-exact HUMAN meeting return · software v22

The v21 focus packet now creates `HUMAN-meeting-review-template.csv` alongside
the original PRIVATE-HUMAN-meeting.json. A human can fill only the exact
original proposal slots with `needs_discussion`, `proposed_followup` or
`hold` and an optional brief private note. The template embeds the unsigned
SHA-256 of the **entire original meeting JSON** on every row.

Copy the edited CSV to original owner-private 0600 storage without distributing
it to other recipients. Then explicitly finalize the **human draft only**:

    python3 assessment-workspace-ledger/portfolio_focus_review.py \
      --portfolio /private/source/PRIVATE-HUMAN-portfolio.json \
      --meeting /private/focus/PRIVATE-HUMAN-meeting.json \
      --review /private/focus/HUMAN-meeting-review-template.csv \
      --private-parent /private/owner-only

The finalizer re-reads original owner-only source portfolio, validates its
strict canonical original bytes, recomputes the meeting's original selected
source slots, requires every submitted row in the original order, refuses
different meeting SHA, duplicate or extra CSV fields, malformed HUMAN text,
formula starts, owner-scope widening and changed source bytes. Only a NEW
0700/0600 PRIVATE/HOLD return folder is created: source-minimal summary,
scriptless original-bound detailed meeting return, native private JSON and
unchanged human CSV. No scheduling, notification, authentic owner identity,
approval, consent, scan, task completion or verified security outcome follows.
Console option **29** performs the same foreground flow; software ZIP v22
includes both original HUMAN meeting producer and native return finalizer.

## Complete PRIVATE HUMAN meeting browser Studio · software v23

The original [portfolio-focus-studio.html](portfolio-focus-studio.html) is a
ready-to-open **single-file, source-free** offline browser application. No
customer/PRIVATE inputs are embedded in the shipped HTML. Open it from a
trusted local folder, explicitly choose the original PRIVATE-HUMAN-meeting.json,
filter the original proposed cases by human priority, proposed owner or
locally chosen review stage, then annotate original historical proposals
without altering the source. Native exact-source SHA-256 is computed from
the selected local input bytes when the browser exposes Web Crypto. No
network, cookies, localStorage, other persistent browser storage, worker,
scan, model, actual scheduling, consent, grant, or automatic dispatch.

The Studio visibly tracks all unsaved HUMAN edits, maintains each original
slot across screen filtering, and exports *ALL* original rows as a native
source-bound CSV that the strict `portfolio_focus_review.py` accepts after
PRIVATE 0600 local custody. Filtering never silently drops source slots.
The browser is only a human interface; native original JSON and unchanged
source bytes are re-admitted and all duplicate keys, unknown source fields,
CSV changes and permission claims are rejected by the original finalizer.

The [portfolio_focus_studio.py](portfolio_focus_studio.py) renderer creates
the same HTML with exact JavaScript and CSS SHA-256 pinned in CSP; the shipped
HTML uses no remotely fetched assets. Generate a new private copy without
overwriting a prior output with:

    python3 assessment-workspace-ledger/portfolio_focus_studio.py \
      --output /private/software/new-human-focus-studio.html

Console option **30** offers this software-only foreground export. Original
software package v23 includes standalone app, its immutable software sources,
both HUMAN meeting steps, and backwards-compatible v16–v22 archive inspection.
Original browser input is never authenticated consent or verified security.

### Source-exact in-memory HUMAN draft resume

The existing standalone offline Focus Studio now has a second explicit local
file picker for a previously exported HUMAN-meeting-review-template.csv.
After the ORIGINAL meeting JSON is selected, the app admits the candidate
CSV as a complete source-exact local proposal: **every** original case /
transition / kit ordinal, row order, exact full-meeting unsigned SHA-256,
allowed human review state and bounded private note must match. Invalid or
partial imports keep current local decisions untouched. A separate HUMAN
confirmation is required before all selections are restored. The original
unsigned browser session never becomes authentication, security evidence,
consent or an authorized decision. The native original source-bound importer
still independently performs all strict admission and creates HOLD-only
PRIVATE returns. The published v23 browser + software ZIP has been refreshed
with these source-only improvements; no PRIVATE input is bundled.

## Multi-version original HUMAN focus review history · source-only v24

[portfolio_focus_history.py](portfolio_focus_history.py) now completes the
offline assessment-human follow-up lifecycle. After at least two distinct
PRIVATE HUMAN return packets have been produced by the original strict native
`portfolio_focus_review.py`, choose their original JSONs in **explicit HUMAN
review order**, together with the identical original owner-only portfolio and
meeting source:

    python3 assessment-workspace-ledger/portfolio_focus_history.py \
      --portfolio /private/source/PRIVATE-HUMAN-portfolio.json \
      --meeting /private/meeting/PRIVATE-HUMAN-meeting.json \
      --return /private/review1/PRIVATE-HUMAN-review-return.json \
      --return /private/review2/PRIVATE-HUMAN-review-return.json \
      --private-parent /private/owner-only

The 2–8 revision PRIVATE history strictly re-admits every previous source
file, requiring original canonical portfolio + full original meeting contents,
each return's exact portfolio/meeting SHA-256, exact review source row
population/order, false authority flags, original kit identities and bounded
private HUMAN notes. Duplicate return bytes, changed source selection or a
different meeting reject the **entire history** before any new output.

New owner-only 0700/0600 artifacts: original source-minimal HTML version
timeline without names, hashes or text; detailed scriptless PRIVATE HUMAN
history HTML; private exact source slot CSV; and canonical source-bound JSON
of HUMAN proposal differences. Previous-to-next HUMAN stage changes and
free-note changes are both exposed as HUMAN proposals, with **no claim that
a security vulnerability was fixed or worsened**. No original client security
data is reopened, no scan or target activity, no notification, real deadline,
appointment, authenticated recipient, consent, grant or production release.

Existing interactive console action **31** runs the identical foreground
history from explicit original files. Software-only bundle v24 adds the native
module and maintains read support for fixed v16–v23 software inventories.
No separate QA/regression/testsuites were authored or executed.

### Resume a full subsequent HUMAN discussion without retyping

The original multi-review history also writes
`HUMAN-next-review-draft.csv`. This is an **unapproved HUMAN draft** copied
from the last explicitly selected original 0600 HUMAN return, in all original
case/transition/kit row positions, with every row bound to the exact original
meeting's unsigned SHA-256. Move it to trusted owner-only private custody and
open it through the existing source-bound Focus Studio restore picker, edit
the HUMAN notes/statuses, then finalize using the original native
`portfolio_focus_review.py`. No assignment, security verification, grant,
consent, actual schedule or work completion is inferred by the carry-forward.
The original review history preserves every earlier version without overwrites.

## Minimum-necessary PRIVATE HUMAN review owner workrooms · v25

A reviewer can now prepare 1–8 **separate, locally staged, proposed HUMAN
owner workrooms** directly from one original PRIVATE-HUMAN-portfolio.json, the
identical source-bound PRIVATE-HUMAN-meeting.json and a finalized original
PRIVATE-HUMAN-review-return.json. Unlike the overall history, the new
[portfolio_focus_owner_handoff.py](portfolio_focus_owner_handoff.py) filters
each output to **only the original source rows that explicitly name that
proposed owner**, including only that subset's original HUMAN priority, date,
next-step text and last HUMAN review state/note.

    python3 assessment-workspace-ledger/portfolio_focus_owner_handoff.py \
      --portfolio /private/source/PRIVATE-HUMAN-portfolio.json \
      --meeting /private/focus/PRIVATE-HUMAN-meeting.json \
      --review-return /private/return/PRIVATE-HUMAN-review-return.json \
      --owner 'Original proposed HUMAN owner A' \
      --owner 'Original proposed HUMAN owner B' \
      --private-parent /private/owner-only

Original strict native source admission is reused; all input bytes are
re-admitted before writing. Empty/duplicate/foreign proposed owner labels,
partial source rows, mismatch with already owner-filtered input or changed
original bytes fail closed. Outputs are one new 0700 parent with opaque
`OWNER-01` etc. 0700 subfolders, each holding independent original-selected
HTML, CSV and canonical JSON (all 0600), and a source-minimal parent overview
without other owner labels or private text. No public server, broker, sending,
access to original client assets, background scheduling, identity assumption
or grant is performed. Every exported proposed name is an unauthenticated
HUMAN label; independently verify permission and recipient before any sharing.

Console option **32** performs this foreground operation. The source-only
offline software bundle v25 includes the owner handoff and maintains v16–v24
fixed software inventory inspection. No tests or QA suites have been added.

## Source-bound PRIVATE HUMAN owner reply round trip · v26

The existing option 32 PRIVATE owner packet now includes an owner-specific
`HUMAN-owner-reply-template.csv`, separately from the original PRIVATE owner
JSON. Every original case/transition/kit source row is bound to the SHA-256 of
the **entire** original owner packet. The HUMAN recipient can edit only
`human_reply_stage` (needs_discussion/proposed_followup/hold) and
`private_reply_note` (<=240 safe characters) in owner-private 0600 storage.

After explicit offline HUMAN editing, the original native
[portfolio_owner_reply.py](portfolio_owner_reply.py) produces a completely new
PRIVATE HOLD-only response:

    python3 assessment-workspace-ledger/portfolio_owner_reply.py \
      --owner-packet /private/owner/PRIVATE-HUMAN-owner.json \
      --review /private/owner/HUMAN-owner-reply-template.csv \
      --private-parent /private/owner-only

The original owner JSON is strictly re-admitted with canonical JSON bytes,
all false authority fields, original source SHA identities, exact bounded
source-row ordinals and owner-only metadata. Complete CSV rows must cover
every original source slot in original order and match the exact owner packet
byte SHA, even when no note was written. Unknown headers, source drift,
duplicated/missing rows, unsupported reply status, formula values and changed
original bytes HOLD without partial output. Outputs use exclusive 0700
PRIVATE directories and 0600 source-minimal summary HTML, detailed PRIVATE
HTML, original-bound response JSON and unaltered source CSV; originals are
never overwritten or deleted.

Console option **33** performs the same deliberate foreground operation.
No real recipient was authenticated by a HUMAN label or unsigned SHA;
independently verify permissions before sharing. No automatic delivery,
scheduling, network activity, active assessment, consent, scope grant,
verified remediation or security PASS. Fixed source-only software v26 includes
the original owner reply flow and retains v16–v25 software inventory reads.

## Complete offline original HUMAN reply inbox · v27

[portfolio_owner_inbox.py](portfolio_owner_inbox.py) completes the
owner-private HUMAN follow-up workflow without any online server, authenticated
user assumption, automatic task assignment or target action. The operator
explicitly selects 1–8 complete triples: ORIGINAL owner JSON from the original
PRIVATE workroom, original native PRIVATE-HUMAN-owner-reply.json and its exact
0600 HUMAN CSV, all from the **same** original 0600 portfolio/meeting/review:

    python3 assessment-workspace-ledger/portfolio_owner_inbox.py \
      --portfolio /private/source/PRIVATE-HUMAN-portfolio.json \
      --meeting /private/meeting/PRIVATE-HUMAN-meeting.json \
      --review-return /private/return/PRIVATE-HUMAN-review-return.json \
      --owner-packet /private/owner1/PRIVATE-HUMAN-owner.json \
      --owner-reply /private/reply1/PRIVATE-HUMAN-owner-reply.json \
      --reply-csv /private/reply1/PRIVATE-HUMAN-original-reply.csv \
      --private-parent /private/operator-only

Repeat **all three** owner-packet/reply/CSV arguments in lockstep, up to eight.
Native original PRIVATE source chain admission first reconstructs every
selected owner packet from the exact original portfolio, meeting and finalized
HUMAN review, rejecting foreign/deleted/modified original rows and
owner-scope widening. Each reply must be canonical, completely source-bound to
the identical original OWNER packet SHA and unchanged CSV SHA, with every
original ordinal matching in the same order, strict human statuses and
bounded private notes. Duplicate HUMAN owners or overlapping original case
slots are refused; any source-byte drift fails the entire inbox before output.
No partial acceptance, no automatic owner identity or grant assertion.

Output: one new exclusive 0700/0600 private HUMAN inbox with counts-only
`OPEN-PRIVATE.html`, scriptless detailed original-owner response HTML,
original-source-reconciled CSV and exact source-bound JSON. All prior PRIVATE
source, owner-packet and human reply files remain untouched. The original
assessment kits are not contacted, and response differences are NEVER proof
of verified remediation. Console option **34** runs this offline foreground
flow; portable software v27 includes the original native source and maintains
fixed software inventory inspection for versions v16 through v26.

## Portable source-free PRIVATE HUMAN owner reply browser · software v28

The new ready-to-open
[portfolio-owner-studio.html](portfolio-owner-studio.html) is a completely
offline, standalone owner reply interface. No source/customer/private HUMAN
bytes are embedded in this software. An operator explicitly chooses their
original local PRIVATE-HUMAN-owner.json. The Studio hashes those exact bytes
locally using Web Crypto, shows each original HUMAN slot with private prior
proposal and discussion notes, filters without dropping hidden original
entries, offers bounded status and note fields, and exports all original slots
as `HUMAN-owner-reply-template.csv`, bound to the exact original owner packet
SHA-256. Browser state is in memory; no network, cookies or persistent
storage. Unsaved edits trigger the browser's leave warning.

The downloaded original HUMAN draft must be transferred to owner-private
0600 custody and passed to the separate native
`portfolio_owner_reply.py` finalizer, which independently rejects changed
source bytes, unexpected CSV or source rows, formula-like private notes,
missing original slots and attempted owner-scope widening. The standalone
HTML is only an unsigned user interface, not reviewer authentication,
recipient permission, client consent or security evidence.

[portfolio_owner_studio.py](portfolio_owner_studio.py) builds a new source-free
offline .html using CSP-pinned local CSS and exact original JavaScript SHA-256:

    python3 assessment-workspace-ledger/portfolio_owner_studio.py \
      --output /private/software/new-owner-reply-studio.html

Console **option 35** offers the same foreground software-only export.
The source-only offline v28 ZIP contains both source scripts and the
ready-to-open standalone app; original v16–v27 software-inventory inspection
remains supported. No external sharing, action dispatch, scan, model,
approval, live consent or deployment is invoked.

### Resume an original owner HUMAN reply draft without source drift

The portable source-free owner Studio now has an optional explicit second file
picker to reopen a previous `HUMAN-owner-reply-template.csv` against the
**exact same original PRIVATE-HUMAN-owner.json**. The complete native column
order, every original case/transition/kit identifier in the original row
order, exact original full owner-packet SHA-256, allowable HUMAN-only statuses
and bounded safe notes must match. Invalid, extra, missing or source-drifted
rows are rejected as a single transaction and existing in-memory HUMAN choices
are never changed. Only after an explicit HUMAN confirmation are those
unapplied local choices restored. No reviewer identity is verified, and native
`portfolio_owner_reply.py` source re-admission remains required before
private HUMAN return creation. No customer data is embedded in software.

## ORIGINAL owner inbox → PRIVATE HUMAN discussion · software v29

The original multiple-owner inbox also writes an owner-private 0600
`HUMAN-inbox-review-template.csv`. Every original case/transition/kit
row is bound to the SHA-256 of the whole unchanged canonical
`PRIVATE-HUMAN-owner-inbox.json`; no human draft is automatically sent.

`portfolio_owner_inbox_review.py` provides a complete local HUMAN
discussion return. It re-admits the original canonical unsigned inbox
file, checks all original owner groups, row population and ordering,
exact inbox source digest in each CSV row, safe proposed discussion stages
and private bounded notes. Any drift rejects the whole submission.

    python3 assessment-workspace-ledger/portfolio_owner_inbox_review.py \
      --inbox /private/inbox/PRIVATE-HUMAN-owner-inbox.json \
      --review /private/inbox/HUMAN-inbox-review-template.csv \
      --private-parent /private/operator-only

The native producer writes a NEW 0700 directory with scriptless counts-only
PRIVATE HTML, detailed PRIVATE HUMAN discussion HTML, source-bound JSON and
unchanged original HUMAN CSV, each 0600. The original source client/owner
packets are not reopened or independently authenticated; this is unsigned
HUMAN discussion, NEVER verified security, recipient, consent, grant,
scan, real assigned task or remediation. Console foreground option **36**.
Software-only v29 includes the original new native module and maintains
fixed source-only software inventory reads v16–v28. No QA suite involved.

## Source-free, offline PRIVATE multi-owner HUMAN Inbox Studio · v30

The ready-to-open [portfolio-inbox-studio.html](portfolio-inbox-studio.html)
is the private operator's locally rendered multi-owner discussion interface.
The shipped software contains no original private source, HUMAN owner, case
or customer data. The operator explicitly selects one original local
`PRIVATE-HUMAN-owner-inbox.json`. The browser hashes the selected exact bytes
using local Web Crypto, previews strict original source slots/owner groups,
shows owner and reply HUMAN statuses, and offers owner/status/text filtering
without dropping ANY original rows from the next source-bound export.

Operators edit only the *new* HUMAN discussion stage and bounded private
discussion note. Export creates the complete original-inbox-SHA-bound
`HUMAN-inbox-review-template.csv` for the original native
`portfolio_owner_inbox_review.py` finalizer (console 36). The same app can
restore a saved entire CSV draft, only when all original slot identities,
unchanged inbox source SHA and HUMAN text values match in source order.
All-or-nothing restore requires an explicit human confirmation. No local
browser persistence, online API, scanning, model, recipient identification,
permission or dispatch. Browser download folders may not be confidential;
move downloaded CSV into 0700/0600 PRIVATE custody before native admission.

The source-only CSP-pinned renderer
`portfolio_inbox_studio.py` builds a NEW private standalone file without
embedding any selected source:

    python3 assessment-workspace-ledger/portfolio_inbox_studio.py \
      --output /private/operator-only/new-private-human-inbox.html

Console foreground option **37** invokes the same local source-only builder.
Fixed source-only offline ZIP v30 ships the HTML, JS, builder and native
inbox review. Previous software inventories v16–v29 remain readable. No
QA/regression/test suites were added or invoked. No security finding or
client consent is asserted by this strictly HUMAN-only editor.

## ORIGINAL source-bound single proposed HUMAN owner follow-up · v31

Once the original 0600 HUMAN inbox discussion has been finalized, the new
[portfolio_owner_attention.py](portfolio_owner_attention.py) produces a
**minimum-necessary PRIVATE discussion handoff** for exactly one explicitly
selected *proposed* HUMAN owner label. It re-admits the original canonical
PRIVATE inbox, original complete unsigned discussion CSV and native finalized
PRIVATE-HUMAN-inbox-review.json, including exact source SHA-256, original
case/transition/kit row ordering, complete original HUMAN decisions,
bounded private notes and every false authority flag. If any original source
changes or a proposed owner is absent, nothing is written.

    python3 assessment-workspace-ledger/portfolio_owner_attention.py \
      --inbox /private/inbox/PRIVATE-HUMAN-owner-inbox.json \
      --discussion /private/discussion/PRIVATE-HUMAN-inbox-review.json \
      --original-review-csv /private/discussion/HUMAN-inbox-review-template.csv \
      --owner 'Exactly original proposed HUMAN owner label' \
      --private-parent /private/operator-only

Exports a new 0700 folder containing only that owner's original source slot
references, previous HUMAN stages, latest proposed HUMAN discussion statuses
and latest PRIVATE HUMAN notes (0600 private HTML, CSV and canonical JSON),
plus a source-minimal count-only PRIVATE HTML with no owner names or notes.
Other proposed owners' rows and free text are intentionally excluded. It
**does not contact or authenticate** this owner and offers no automatic
recipient delivery or sharing permission, assessment scan, authorized task,
scope grant, verified finding or remediation. Independent authenticated
recipient review is necessary before any manual transfer.

Console foreground action **38** exposes the same bounded offline export.
The source-only v31 software bundle includes the original code, still
supporting fixed software inventory inspection v16–v30, without QA suites.

### Bulk HUMAN discussion for one explicitly selected original owner · v31

The source-free Inbox Studio now allows an operator to choose exactly one
original proposed HUMAN owner and apply a HUMAN-only proposal stage to just
the **currently visible** matching rows, after an explicit local confirmation.
Original sources, original owner reply stages, private HUMAN notes and
invisible rows are untouched. No owner filter means no bulk action. The CSV
export still retains **all** original source rows in exact original order,
regardless of filtering or mass HUMAN draft edits. Changes are still unsigned
local concepts; the native original-inbox-bound finalizer remains mandatory.
No real task assignment, authenticated receiver, consent or scan is created.

## v32 — exact original PRIVATE HUMAN inbox discussion history · console 39

The source-bound inbox reviewer already permits more than one independently
completed HUMAN-only discussion, but earlier operators could not compare their
proposed changes without manually inspecting separate PRIVATE HTML packets.
New [portfolio_inbox_history.py](portfolio_inbox_history.py) reads **2–8
explicitly ordered ORIGINAL finalized inbox review JSONs**, each with its exact
original HUMAN review CSV, alongside a single original 0600
`PRIVATE-HUMAN-owner-inbox.json`. All original inputs must be separate absolute
paths. Every version is admitted by the **existing native**
`portfolio_owner_attention.read_discussion`, including original exact-inbox
byte SHA, corresponding CSV byte SHA, canonical schema, all required false
authority flags, all original HUMAN row identity/order, and all HUMAN stage/note
values. Repeated byte-identical finalized rounds are rejected.

    python3 assessment-workspace-ledger/portfolio_inbox_history.py \
      --inbox /private/inbox/PRIVATE-HUMAN-owner-inbox.json \
      --discussion /private/review1/PRIVATE-HUMAN-inbox-review.json \
      --review-csv /private/review1/HUMAN-inbox-review-template.csv \
      --discussion /private/review2/PRIVATE-HUMAN-inbox-review.json \
      --review-csv /private/review2/HUMAN-inbox-review-template.csv \
      --private-parent /private/operator-only

The original source is re-admitted and all exact original HUMAN review CSV/JSON
bytes are re-opened before any derived PRIVATE output is allocated. One new
0700 output room contains a minimal anonymous `OPEN-PRIVATE.html` with
human-stage/changed-note counts only; owner-private 0600 detailed scriptless
HTML, CSV and canonical JSON report original source slot and owner label, all
HUMAN proposed stages and transition round numbers. **Derived history never
includes private free-text note contents**, only whether those changed between
adjacent manually ordered rounds. Source identities, packet digests and labels
stay inside 0600 outputs. Original input files remain unchanged. No dates or
meeting attendance are inferred from round positions.

Console **39** provides the foreground flow. Fixed source-only software bundle
**v32** includes the module and retains **v16–v31 read-only package inventory**
compatibility. No scanner, actual client, network, auth, grant, notification,
worker, recipient transfer, scheduling, real remediation proof or security PASS.
The original stage stays **INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD**; release
gates remain unchanged.

## v33 — minimum-necessary proposed HUMAN owner history · console 40

For a single explicitly proposed original HUMAN owner, v33 adds optional
`--owner 'Exact original owner label'` to the original
`portfolio_inbox_history.py` command (also console **40**). The same strict
native input chain admits EVERY original owner and HUMAN round before export.
The output filters to only this exactly matching owner; if missing, HOLD,
never an implicit fallback to all owners.

Creates a separate 0700 PRIVATE room with 0600 scriptless detailed HTML,
CSV, canonical JSON and source-minimal count-only OPEN-PRIVATE.html. Only the
selected owner's source slots, stages and note-changed flags appear; private
free-text note content is never copied. Original complete source/round
SHA-256 references are recorded as unsigned provenance, not authentication
or permission to send. Neither selecting an owner label nor reviewing these
private discussions constitutes actual identity, consent, authorization,
remediation, real tasks, notification or scan.

Usage: repeat the original v32 `--discussion` and `--review-csv` pairs,
append `--owner 'Exact proposed HUMAN owner'`, then choose one existing
owner-private 0700 `--private-parent`. No output is written on original
owner/source mismatch. The v33 source-only software ZIP retains read-only
inspection of historical fixed software v16–v32. All release, source-owner,
security, privacy, and CI/HUMAN GO gates remain intact.

## v34 — PRIVATE changed-only HUMAN discussion brief

Historical HUMAN source review can now create two additional PRIVATE 0600
artifacts in the same new 0700 output room:
`PRIVATE-HUMAN-changed-only.html` and
`PRIVATE-HUMAN-changed-only.csv`. They contain **only original rows whose
HUMAN-proposed stage or PRIVATE human note changed between adjacent manually
ordered rounds**. The rows show original proposed owner, original source slots,
first/latest human-only stage, exact human round numbers where proposals changed,
and the note-changed round numbers, **never private note text**. If none changed,
the private HTML explains explicitly that this does not prove a fix.

Both full-operator (console 39) and *one exact proposed HUMAN owner only*
(console 40) modes support this narrower briefing; other owners' data never
enters an owner-scoped brief. All original native source re-admission and
owner-private 0700/0600 custody remain unchanged, with no new grant, target,
scan, task assignment, notification or release. Source-only ZIP **v34**
retains legacy unsigned v16–v33 inventory inspection.

## v35 — offline PRIVATE HUMAN timeline explorer + native round handoff

The original multi-round inbox-history producer now places a **ready-to-open
PRIVATE-HUMAN-history-explorer.html** inside each new 0700/0600 operator-private
history output room. Open it locally in a compatible browser, explicitly
select that room's already-created native
`PRIVATE-HUMAN-inbox-history.json`, and inspect the original HUMAN-only
discussion timeline without reassembling a CLI invocation.

New [source-free standalone offline browser](portfolio-inbox-timeline.html)
and original source [portfolio_inbox_timeline.js](portfolio_inbox_timeline.js)
offer:
- Exact historical original case/transition/kit cards and HUMAN proposal
  progression for **2–8 manually ordered rounds**, never claimed timestamps.
- Round selector, original proposed-owner filter, stage selection, local search
  and separate filters for stage changes, changed-private-note flags, stable
  proposals or any HUMAN-only changes.
- Anonymous **visible-counts JSON** for filtered proposed HUMAN stages, with
  **no source ordinals, HUMAN owner labels or SHA fingerprints**.
- PRIVATE CSV export only after an **explicit individual original proposed
  HUMAN owner** has been selected and a separate HUMAN confirmation accepted.
  Exports only that owner's currently visible source slots. No private
  HUMAN note content is ever copied into the derived history or CSV.
- Owner-scoped original history remains owner-scoped on import: the browser
  cannot broaden the original source selection.
- No JS network APIs, cookies, localStorage, server, background processing,
  browser downloads of original source bytes, grants, scans or authenticated
  receiving. Native original-bound input rejection remains authoritative;
  the browser schema/digest preview is **unsigned**, not security attestation.

The existing new software-only [portable viewer](portfolio-inbox-timeline.html)
ships inside fixed offline software package **v35**, with original older
v16–v34 inventory read compatibility. Operators can also generate a fresh
source-free CSP/SHA-pinned copy into an existing owner-private 0700 folder:

    python3 assessment-workspace-ledger/portfolio_inbox_timeline.py \
      --output /private/software/NEW-HUMAN-history.html

Foreground console **41** performs the same software-only operation.
The original history producer (console 39 or single-original-owner console
40) automatically creates a separate private HTML copy for each history.
Only the operator can manually select original history source bytes later.

**Posture unchanged:** Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD. No actual
security finding, verified fix, target, grant, task assignment, consent,
reviewer identity, live scan, release or communication is inferred.
Original exact-head hosted and permanent named VPS CI, original source-holder
and independent security/privacy/browser review, #177/#182/#829, authenticated
separate current client/operator consent with action-time revocation, and
explicit HUMAN GO continue to gate main merge/deployment.

## v36 — complete source-exact PRIVATE HUMAN owner selection round-trip

The offline v35 history explorer now exports an explicitly owner-scoped HUMAN
selection CSV containing the **exact full SHA-256 of the loaded original native
PRIVATE-HUMAN-inbox-history.json** and the manually selected original HUMAN
round. The browser never exports other HUMAN owners, private free-text notes
or original input bytes. The CSV is for trusted PRIVATE re-admission, not
authorization; it is unsigned and could have been locally edited.

New [portfolio_inbox_timeline_selection.py](portfolio_inbox_timeline_selection.py)
and console **42** implement the critical native receiving step. They read
one original canonical 0600 native history JSON with duplicate-key refusal,
strict no-follow descriptor bounds, every false authority flag, original owner
scope, all exact human source slot identities, 2–8 ordered original round
digests, stage sequences and note-changed flags. They read the complete exact
CSV, require its source SHA to match original canonical history **bytes**,
require identical chosen HUMAN round on every original selected row,
reject duplicate/extra/edited/foreign/other-owner/out-of-order rows, and
require the explicit original proposed HUMAN owner filter. A prior
owner-scoped source cannot widen to additional owners.

    python3 assessment-workspace-ledger/portfolio_inbox_timeline_selection.py \
      --history /private/history/PRIVATE-HUMAN-inbox-history.json \
      --selection-csv /private/downloads/LightUp-PRIVATE-HUMAN-owner-visible.csv \
      --owner 'EXACT original proposed HUMAN owner' \
      --private-parent /private/operator-only

Before writing, both original PRIVATE inputs are re-read byte-exactly. The
native tool creates an exclusively new 0700/0600 owner-private room with
an anonymous counts-only scriptless OPEN-PRIVATE.html and source-bound
`PRIVATE-HUMAN-history-selection.html`, canonical JSON and the exact
original CSV. Free-text original HUMAN notes are not included. Only one
original selected owner and selected human-only source slots appear in
the private detail. No original packets or files are overwritten.

**Important:** Re-admitting an unsigned native-derived history + unsigned
browser CSV checks byte identity and local structure, not independent
provenance of earlier source kits or authenticity of client/operator consent.
The original native upstream workflow must remain separately trusted;
manual recipient verification and privacy/authorization review remain
mandatory before sharing. This is **never** an assignment, security finding,
client authorization, grant, scan, communication or release decision.

New source-only **v36** ZIP includes the full browser → private native
receiving workflow and the fixed unsigned v16–v35 inventory reader. Notion
Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD and all original CI/review/consent/
HUMAN GO gates remain unchanged.

## v37 — separate PRIVATE HUMAN owner timeline batch · console 43

New [portfolio_inbox_timeline_batch.py](portfolio_inbox_timeline_batch.py)
receives 1–8 *separate* browser-generated original HUMAN owner selection CSVs
against exactly ONE original native PRIVATE-HUMAN-inbox-history.json.

    python3 assessment-workspace-ledger/portfolio_inbox_timeline_batch.py \
      --history /private/history/PRIVATE-HUMAN-inbox-history.json \
      --owner 'Owner A' --selection-csv /private/a/PRIVATE-selected.csv \
      --owner 'Owner B' --selection-csv /private/b/PRIVATE-selected.csv \
      --private-parent /private/operator-only

All owners, all original native history details and **all exact CSVs** are
validated up front through the existing strict canonical original history
and selection admission, with duplicate/foreign/overlapping owner or case
slots refused. Any historical single-owner source cannot be widened.
Original source and all owner CSV bytes are reread before any output.
On success one new 0700 root contains independently created 0700 PRIVATE
owner-only subrooms with each original HUMAN CSV, 0600 canonical JSON,
detailed HTML and anonymous counts. The root's private scriptless
OPEN-PRIVATE.html lists only packet ordinals, round and counts with local
links, not source identities or owner labels. A separately stored 0600
operator-only batch manifest records proposed owner-to-subroom mapping.
Failures remove only the incomplete new output tree, never sources.

No actual sending, recipient authentication, authorization, consent, scan,
grant, verification, assignment or remediation claim. A proposed owner label
is not an authenticated recipient. Source hashes are unsigned byte identities.
Foreground console **43** exposes this original HUMAN-only batch workflow.
Fixed source-only package **v37** retains v16–v36 inventory reads.
Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD and all exact original CI, owner,
security/privacy/browser review and HUMAN GO gates remain unchanged.

## v38 — refuse duplicate source JSON keys in HUMAN history browser

The complete standalone offline HUMAN history viewer now recursively rejects
repeated original JSON keys before showing any timeline, including duplicate
keys with different Unicode escape spellings. This prevents a locally edited
PRIVATE import from silently replacing earlier keys in the browser preview.
Noncanonical or corrupted inputs still require the separate native source
reader; the browser is never permission, signature validation, true
authentication or provenance proof.

Fixed source-only bundle **v38** replaces the source-free HTML and JS viewer,
and maintains v16–v37 unsigned software inventory inspection. No original
PRIVATE input, target, client, grant, scan, model, network, action or
authorization was activated. All original Incubate M3/M7 HUMAN GO and exact
hosted/named VPS CI plus independent owner/security/privacy/browser gates
remain unchanged.

## v39 — complete PRIVATE HUMAN owner response against original source

A new [portfolio_inbox_owner_return.py](portfolio_inbox_owner_return.py)
closes the missing **human reply** step after original history selection.
This operator-only CLI prepares a complete owner-private HUMAN reply template,
then independently re-admits the owner-edited file into a new PRIVATE
receipt. No real tasks or authenticated recipient are implied.

To prepare an original owner-only CSV template using already-produced native
history and selection files:

    python3 assessment-workspace-ledger/portfolio_inbox_owner_return.py prepare \
      --selection /private/owner/PRIVATE-HUMAN-history-selection.json \
      --history /private/history/PRIVATE-HUMAN-inbox-history.json \
      --selection-csv /private/owner/PRIVATE-HUMAN-original-selection.csv \
      --private-parent /private/operator-only

The native producer reads the complete original canonical history and the
existing originally selected HUMAN CSV using the **unchanged existing native
validators**. It verifies the complete selected original owner packet,
original review round, source SHA and all original HUMAN case rows. A new
0700/0600 owner PRIVATE room contains a full
`HUMAN-owner-history-reply-template.csv` and scriptless HUMAN instructions.
Every original row remains present in exact order; only the proposed HUMAN
reply stage and 240-character private HUMAN note are editable.

After the HUMAN proposes a reply in a genuinely PRIVATE local copy, use:

    python3 assessment-workspace-ledger/portfolio_inbox_owner_return.py receive \
      --selection /private/owner/PRIVATE-HUMAN-history-selection.json \
      --history /private/history/PRIVATE-HUMAN-inbox-history.json \
      --selection-csv /private/owner/PRIVATE-HUMAN-original-selection.csv \
      --reply-csv /private/replies/HUMAN-owner-history-reply-template.csv \
      --private-parent /private/operator-only

The native re-admission enforces exact original selection-byte-SHA across
the full CSV, identical original owner-row ordinals, original HUMAN stages,
matching fixed CSV schema, complete row population, bounded and
formula-safe private HUMAN notes, and only three historical HUMAN status
values. All original source/csv bytes are re-read before publishing a new
exclusive 0700 PRIVATE room with scriptless summary, detailed 0600 HTML,
canonical source-bound 0600 JSON and unchanged original HUMAN CSV.
Original inputs are never modified.

Foreground console **44 prepare** and **45 receive** provide the complete
same-source manual workflow. Neither a HUMAN label nor an unsigned SHA
authenticates a real recipient. No external send, network, scanner, model,
grant, consent, verified remediation, task creation, action or security PASS.
Every original release gate remains mandatory; PR stays DRAFT/HOLD at Notion
Incubate M3/M7 PLAN/LAB ONLY. Source-only software bundle v39 maintains
read-only unsigned v16–v38 software inventory inspection.

## v40 — source-free PRIVATE HUMAN owner reply browser (complete round-trip)

The v39 original HUMAN owner reply prepare/receive command now includes
a ready-to-open **PRIVATE-HUMAN-owner-reply-studio.html** in every new 0700
owner-private preparation room. The same source-free, CSP/SHA-pinned app ships
as [portable software](portfolio-inbox-owner-return-studio.html).

The HUMAN operator explicitly selects one original private
`PRIVATE-HUMAN-history-selection.json`; the browser checks the bounded
offline JSON fields, literal all-false authority flags, one original proposed
owner, the original source slots and proposed stage, then computes the SHA-256
of the original exact local input bytes. No real client, recipient or
PRIVATE review data is embedded in the software ZIP.

Per original owner slot the offline app shows original selected-human stage,
case/transition/kit, HUMAN stage-change numbers and note-changed flags. HUMAN
can propose one of three HUMAN-only stages and a bounded PRIVATE reply note;
filter/search never drops hidden original rows from the **complete** CSV.
The app exports a whole original-selection-SHA-bound
`HUMAN-owner-history-reply-template.csv` compatible with v39 native
`portfolio_inbox_owner_return.py receive`. An older COMPLETE HUMAN draft
can be locally reopened only if original byte SHA, row order, stage and note
values agree for every original source slot, after a separate HUMAN
confirmation. Invalid/foreign drafts never overwrite existing local choices.
Duplicate original JSON keys are refused before any preview. Browser
memory is not persistent and there are no network requests.

The independent native receiving step still requires the original private
history, native selection and original CSV and re-admits every owner-only
slot, source hash, review round, complete proposed reply and safety flag.
Browser local SHA is unsigned and **never authenticates a HUMAN recipient**.

To build additional portable source-only copies inside an existing PRIVATE
software folder:

    python3 assessment-workspace-ledger/portfolio_inbox_owner_return_studio.py \
      --output /private/software/NEW-ORIGINAL-owner-reply-studio.html

Console **46** exposes the source-only offline builder; 44→46→45 is the
complete private HUMAN-only response workflow. Software package v40 includes
all modules and prior fixed unsigned v16–v39 inventory inspection. No sending,
grants, scans, actual tasks, verified security findings, consent or approval.
Notion Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD, source-owner and independent
security/privacy/browser reviews, exact hosted/named VPS CI, #177/#182/#829,
separate authenticated current client/operator consent with action-time
revocation and explicit HUMAN GO remain mandatory before any main release.

## v41 — complete 1–8 ORIGINAL HUMAN owner response operator inbox

The new [portfolio_inbox_owner_reconcile.py](portfolio_inbox_owner_reconcile.py)
finishes the HUMAN-only owner reply loop after v39–v40 prepare/edit/receive.
It accepts 1–8 separate explicit quadruples:
`--selection` original PRIVATE-HUMAN-history-selection.json,
`--selection-csv` its exact selected source CSV,
`--reply` its original native PRIVATE-HUMAN-owner-history-reply.json,
and `--reply-csv` its complete edited original HUMAN reply CSV.
All selected owner packets must share the exact same original
`--history PRIVATE-HUMAN-inbox-history.json` and one already-existing PRIVATE
`--private-parent`. Repeat all four options together per original owner.

The producer reuses the original canonical source_history and source_selection
parsers and original HUMAN reply CSV admission. It rejects owner-group reuse,
overlapping local-case/transition/kit ordinals, altered HUMAN stages or note
values, changed original source/selected/reply CSV hashes, nonfalse authority
flags, or any foreign/dropped/excess original slot. Source bytes for every
input are independently re-admitted before the new private output is made.
No partial acceptance or original input overwrite.

Result: an exclusively new 0700 owner-private operator room with scriptless
count-only `OPEN-PRIVATE.html`, detailed 0600 operator
`PRIVATE-HUMAN-owner-inbox.html`, complete original-human-only CSV and
canonical source-bound 0600 JSON. The summary intentionally contains no
owner labels, private notes, source slot identifiers or SHA hashes.
Confidential complete HUMAN note texts appear only in the private operator
detail; this is not approved for automated recipient disclosure.

Foreground console **47** exposes this same offline multi-owner workflow.
No dispatch, external API, real target, assessment, consent, grant, actual
task, verified fix or independent reviewer authentication is executed.
Source-only v41 preserves original v16–v40 software inventory reads. Notion
posture Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD and all original source-owner,
CI, independent security/privacy/browser-review, action-time client/operator
consent and explicit HUMAN GO release gates remain unchanged.

## v42 — source-free interactive HUMAN reply operator inbox

Every new native v41 operator-only multi-owner response room now also contains
a ready-to-open source-free `PRIVATE-HUMAN-owner-inbox-viewer.html`.
Use it offline to explicitly load its matching native
`PRIVATE-HUMAN-owner-inbox.json` from 0600 PRIVATE custody. The portable
[operator viewer](portfolio-owner-inbox-viewer.html) is also included in the
source-only ZIP, without embedded owner, client, source or HUMAN note bytes.

The CSP/SHA-pinned browser provides original owner-group filters, proposed
HUMAN reply-stage filters, unchanged/changed HUMAN proposal filters, local
PRIVATE text/source search, a readable original-source case/transition/kit
discussion view and anonymous VISIBLE HUMAN-counts export. Filters never
alter the native source. Anonymous exports omit all private notes, proposed
owner names, case identities and SHA references. Local PRIVATE note text is
visible only in the operator's original local browser session; it is not
automatically exported, persisted or sent. Duplicate-key JSON input is
rejected before any local preview. Original native validators remain
authoritative; a browser preview is not identity, consent, authorization,
security evidence, verified remediation, or permission to share.

The source-free viewer can also be rebuilt into an existing operator-private
0700 folder without touching historical original source inputs:

    python3 assessment-workspace-ledger/portfolio_owner_inbox_viewer.py \
      --output /private/software/NEW-HUMAN-reply-inbox.html

Foreground console **48** exposes the source-only builder; original native
console **47** automatically includes the complete offline viewer.
Source-only fixed software **v42** includes the whole HUMAN-only return loop
and preserves read-only inventory compatibility with original v16–v41 bundles.
Release status remains Notion Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD; no
active scans, grants, client data processing, external communication,
authenticated operator/client consent, HUMAN GO or production deployment.
