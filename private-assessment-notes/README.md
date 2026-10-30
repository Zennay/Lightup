# LightUp · PRIVATE credential-masked HUMAN assessment notes

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Complete local, non-authorizing HUMAN review product on the original Basic/Bearer/API-key credential redaction boundary. No target interaction, scan, model invocation, upload, customer notification, approval, deployment, retest, or release.

### Original-source revision handoff (offline, fail-closed HUMAN)

When the original source notes change, **never** resume a previous
`HUMAN_REVIEWED` or owner-private status packet directly into a different
workroom. Instead generate a **new** original-bound PRIVATE workflow with
`har-review-start` for the revised files, and explicitly compare it to
the previously retained original private workflow and one source-bound
HUMAN status report:

~~~sh
python3 private-assessment-notes/notes.py har-review-revision \
  --older-workflow /private/old/PRIVATE-lightup-har-workflow-... \
  --newer-workflow /private/new/PRIVATE-lightup-har-workflow-... \
  --older-progress-room /private/old/PRIVATE-lightup-har-human-status-... \
  --private-parent /private/new
~~~

The new owner-only 0700 `PRIVATE-lightup-har-revision-...` contains
`OPEN-PRIVATE-HAR-REVISION.html` (scriptless, source-minimal original
position summary and per-action decision reasons),
`PRIVATE-HAR-REVISION-decision-guide.csv` (original ordinal, review
area, earlier HUMAN status, proposed status and conservative reason),
`PRIVATE-HAR-REVISION-edited-actions.csv` (a **strict new-workflow
template-compatible** complete proposed CSV), and an unsigned
source-bound HOLD receipt. The four generated files are owner-only
0600. No raw source content, original filename, credential, client
identity, URL, source hash, HUMAN note or remote recipient is copied.

The comparison matches **the same original ordinal and exact original
input/derived bytes**, not inferred source identity. Any changed, added,
removed or moved original position is flagged for new private HUMAN
review. Prior `HUMAN_REVIEWED` is **always reset to
`PENDING_HUMAN`**, even if source and task appear unchanged. Earlier
`WITHHOLD` is conservatively retained across every task for that same
ordinal even when source bytes have changed. Other unapproved HUMAN
statuses may carry only when the original input bytes and task identity
match exactly. All proposed statuses remain unverified and do **not**
imply privacy clearance, consent, release or permission to scan.

Open the **new** HAR Status Studio, choose its local CSV resume picker
and inspect this revision's proposal. Perform real HUMAN review of the
revised original sources, export a complete NEW edited CSV, keep it
owner-only 0600 and manually run `har-review-progress` against the
**new** workflow. No revision tool automatically imports, approves or
dispatches anything. Output remains HOLD (3).

`har-review-revision-reopen` with the same
`--older-workflow`, `--newer-workflow`,
`--older-progress-room` and `--revision-room` reconstructs and
compares every source-bound output byte read-only. Only owner-private
directories and previously immutable original v19 cue receipts are
admitted. Unsigned local hashes are not independently authenticated
timestamps, consent, identity, proof of complete redaction or safety.
Existing exact-head CI and independent HUMAN reviews remain mandatory.

### Original-bound PRIVATE HAR HUMAN operations desk

After the first full manual status import, `har-review-progress`
**automatically** generates both a fresh original-bound 0600 HUMAN
progress packet and a separate scriptless **`OPEN-PRIVATE-HAR-DESK.html`**.
The desk is saved as a new 0700 owner-private sibling folder; it never
mutates the source, v19 cue workroom or earlier review packets. Creation
is all-or-nothing: incomplete fresh status/desk folders are rolled back.

The desktop view offers original-position manual next-action navigation,
links to the original masked HUMAN notes, status Studio, original
workflow, all admitted earlier status packets and the latest editable
CSV. It groups original actions, shows latest and prior operator-typed
statuses, changed rounds, reopened HUMAN-review labels and an explicitly
**non-security-severity** manual work order. Its two source-minimal exports
are `PRIVATE-HAR-NEXT-ACTIONS.csv` (per action) and
`PRIVATE-HAR-SOURCE-QUEUE.csv` (per original ordinal); an unsigned
`PRIVATE-HAR-DESK-receipt.json` binds all outputs and progress receipts.
No source contents, filenames, client identities, source hashes or HUMAN
free text are embedded. Statuses do not certify anything.

To include earlier HUMAN reports in the next desk, supply up to seven
`--previous-round /private/owner-room/PRIVATE-lightup-har-human-status-...`
arguments on `har-review-progress`. Each progress room must be an
unchanged, original-bound, owner-only **sibling** directory, and the
output `--private-parent` must be the workflow parent (same local
relative-link scope). The new review packet is last; prior order is
operator-supplied, not verified chronology.

Existing earlier rounds can instead be viewed without a new status
import:

~~~sh
python3 private-assessment-notes/notes.py har-review-desk \
  --workflow-room /private/owner-room/PRIVATE-lightup-har-workflow-... \
  --progress-room /private/owner-room/PRIVATE-lightup-har-human-status-... \
  --private-parent /private/owner-room
~~~

A previously built private desk can be independently reopened byte-for-
byte via `har-review-desk-reopen --workflow-room ... --progress-room ...
--desk-room ...`, preserving identical operator round order. Both desk
commands return HOLD (3); no standalone browser status, risk score,
client consent or release right is ever inferred.

### Single-command PRIVATE HAR HUMAN workflow

A new `notes.py har-review-start` produces **three owner-only local
0700 workrooms in one action**: the unchanged original redacted HUMAN
notes, an independently original-bound v19 HAR cue packet, and a
scriptless local `OPEN-PRIVATE-HAR-WORKFLOW.html` linking both.
Source inputs must be 0600 and the preexisting parent 0700:

~~~sh
python3 private-assessment-notes/notes.py har-review-start \
  --source /private/original-note.txt --private-parent /private/owner-room
~~~

`har-review-reopen --workflow-room <workflow>` re-admits the original
source/cue receipts and checks the exact launcher bytes, read-only.
`har-review-progress --workflow-room <workflow> --edited-actions
<owner-only-edited.csv> --private-parent <owner-room>` accepts a separate
0600 CSV via the original native HUMAN status admission.
`har-review-progress-reopen`, `har-review-history` and
`har-review-history-reopen` provide the same original-bound flow using
one workflow reference rather than manually joining original/cue paths.

No old packet is overwritten. On partial preparation failure only new
workrooms from this invocation are removed; original selected input files
remain unchanged. The HTML contains only random local sibling directory
names and original-source count, not source filenames, content, URLs, SHA,
clients, secrets or HUMAN notes. This workflow is strictly offline and
PRIVATE/HOLD. Human CSV downloads must be manually chmod 0600 before
native processing. No consent, authorization, privacy verdict, source
owner signoff, active scan, disclosure or deployment is inferred.

### New: fully offline PRIVATE HAR HUMAN Status Studio (v19)

The original owner-private workroom and independently source-bound masking
cue packet now also generate **`PRIVATE-HAR-STUDIO.html`**, a self-contained
HUMAN task editor. Open it locally; it embeds only original ordinals, fixed
review questions and literal marker counters (no original source bytes,
filenames, URLs, digests, client names or HUMAN notes).

- Filter by task text/original position or manual status; **all** originals
  remain in every complete CSV export, including currently hidden rows.
- Propose a HUMAN status per task, bulk-apply **only non-reviewed states**
  to visible rows, and undo the previous bulk change. `HUMAN_REVIEWED`
  can only be selected individually, and is never an approval or verdict.
- Save a complete `PRIVATE-HAR-ACTIONS-edited.csv`. The output is
  compatible with the existing native `notes.py har-action-progress`.
  Download permissions are browser-dependent: move it into owner-private
  0700 storage and **chmod 0600 before any native import**.
- Resume a previous original-bound PRIVATE edited action CSV locally.
  Admission is all-or-nothing: exact original roster, task order, question,
  counts and permitted status fields are required. No source, API,
  scanner, model, browser storage, network, recipient or grant is accessed.

The browser cannot run native `har-action-progress`; this still must be
called separately by an explicitly responsible HUMAN operator. Native
source-bound admission, workroom permissions, no-free-text constraint,
read-only reopening and **HOLD** results are unchanged.

The new **v19** masking-cue receipt additionally binds the exact generated
offline studio HTML bytes. Prior v1–v18 packets are opened with their
unchanged historical receipt and generated file expectations. New HTML
source pins its own inline JavaScript with an exact SHA-256 CSP hash, has no
remote scripts and offers no release or execution mechanism.

### New: source-bound PRIVATE HAR multi-round history

After creating 2–8 separate original-bound `har-action-progress` packets
from the same original kit and immutable v18/v19 masking-cue room, the source
owner can view literal HUMAN status transitions without copying evidence:

~~~sh
python3 private-assessment-notes/notes.py har-action-history \
  --original-kit /private/original-kit \
  --cue-room /private/immutable-cues \
  --round /private/human-status-first \
  --round /private/human-status-second \
  --private-parent /private/owner-work
~~~

The CLI read-only re-admits every original packet and task row before
writing a new 0700 room containing `PRIVATE-HAR-HISTORY.html` (scriptless),
`PRIVATE-HAR-HISTORY.csv` and a byte-bound unsigned HOLD receipt.
The overview shows original position, task area, literal cue counts, each
manual status, changed rounds and reopened-after-HUMAN_REVIEWED indicators.
No source names/paths/URLs/hashes, raw data, reviewer identity or free-text
notes appear in HTML/CSV. Round order is declared by the operator, not
authenticated chronology; all HUMAN statuses remain unverified.

Reopen the exact immutable receipt with the same ordered `--round`
arguments and `notes.py har-action-history-reopen --original-kit ...
--cue-room ... --history-room /private/PRIVATE-lightup-har-review-history-<id>`.
It checks unchanged original source, all input rounds, and all report bytes.
Both native actions always return HOLD (exit 3). No status transition means
consent, privacy review, permission to scan, grant or release.

### New: source-bound original HAR HUMAN action worksheets (v18)

The original PRIVATE source-owner workroom now emits
`PRIVATE-HAR-ACTIONS.html` (printable, scriptless) and
`PRIVATE-HAR-ACTIONS.csv` (manually editable task template).
Every original ordinal receives a mandatory **full original review** task,
even when all cue counters are zero; a completely withheld derived copy
gets an additional **SOURCE OWNER REQUIRED** task. Visible HAR category
markers create separate original-position tasks. The CSV has an unfilled
HUMAN notes column and initial `PENDING_HUMAN` statuses; updating it
is a private manual coordination action, **not** native consent, clearance,
finalisation or an accepted input to any assessment execution.

No original source names, paths, URLs, hashes, content, identifiers or
reviewer notes are read into the generated worklist. Literal marker counts
are not real detections or proof of effective credential masking. Edited
task CSVs are **not** the immutable source-bound receipt. The unchanged
original PRIVATE HUMAN decision workroom is the sole local decision path;
all decisions remain HOLD without independent review and HUMAN GO.

With `notes.py prepare --with-mask-cues` the two worksheets appear in the
fresh original owner-private kit. The independent `notes.py masking-cues`
creates the same files with immutable byte-level receipt admission.
`notes.py masking-cues-reopen` verifies unedited v18 action HTML/CSV
against the unmodified original source; earlier v1–v17 cue packets
reopen using their exact original historical algorithms. **Do not edit
receipt-bound originals.** Copy the editable CSV elsewhere, keep owner-only
permissions, and treat all copies as PRIVATE/HOLD.

### New: original-bound manual HAR progress import (offline)

After creating an **independent** immutable v18 masking-cue packet,
copy its `PRIVATE-HAR-ACTIONS.csv` to a *different*, owner-private 0600
file. Edit only the `human_status` column for individual task rows,
choosing `PENDING_HUMAN`, `IN_PROGRESS`, `HUMAN_REVIEWED`,
`SOURCE_OWNER_NEEDED` or `WITHHOLD`. Leave `human_notes` blank.
Never edit the original cue packet or change action identity, order,
ordinal, count or task name.

~~~sh
python3 private-assessment-notes/notes.py har-action-progress \
  --original-kit /private/original-prepared-kit \
  --cue-room /private/original-independent-v18-cue-room \
  --edited-actions /private/edited-HAR-ACTIONS.csv \
  --private-parent /private/operator-lightup-work
~~~

This command read-only re-admits the exact original source-bound masking
receipt, checks all original v18 files and every unchanged CSV task before
accepting a manually typed status. It produces a fresh owner-only PRIVATE
0600 `PRIVATE-HAR-HUMAN-status.html`, source-minimal
`PRIVATE-HAR-HUMAN-status.csv`, and unsigned input-hash receipt. It also retains the admitted exact
owner-private edited actions CSV (with **no free-text notes**) so the
original immutable report can be reopened without replacing any old
review or source packet.

~~~sh
python3 private-assessment-notes/notes.py har-action-progress-reopen \
  --original-kit /private/original-prepared-kit \
  --cue-room /private/original-independent-v18-cue-room \
  --progress-room /private/PRIVATE-lightup-har-human-status-<actual-id>
~~~

The read-only reopen reconstructs each status HTML/CSV byte, checks
the edited-input SHA, original template SHA, complete action identities,
unsigned HOLD receipt and all original cue bytes. Missing or changed
rows, edited report bytes or replaced original files refuse with HOLD.
All v18 progress outputs are separate owner-only 0700/0600 workrooms;
this receipt is an integrity binding, **not** a signature or human identity
attestation. Never infer real client/operator approval from a typed status.
Free-text notes cannot enter the derived status page. The original
decision workroom, original notes, original cue packet and edited input
remain unchanged. Missing/extra/moved tasks, replaced source, changed
receipt, unexpected statuses and nonempty free-text notes refuse.
A successful PRIVATE report **still returns HOLD (exit code 3)**.
`HUMAN_REVIEWED` is only an unverified typed status — never identity
attestation, external sharing permission, consent, finding, risk decision,
authorisation, scan, release or automatic approval.

### New: conservative HAR source-content withholding

For newly generated **owner-private** workrooms, the original source-bound
offline note redactor now withholds entire `request.postData.text` and
`response.content.text` string bodies from structurally valid bounded HAR
JSON, as well as text data/payload within Chrome HAR `_webSocketMessages`.
HAR cookie values with unrecognized application-specific names are also
withheld in PRIVATE output. Original HAR request queryString and
postData.params string values are withheld even with unknown application
field names. Headers, timing, original field names and HUMAN review flow
remain available. Original HAR request URLs, response redirects,
all string HTTP header values (including unknown custom headers) and form
upload file references are now withheld from PRIVATE derivatives.
An ambiguous, embedded, malformed or over-limit HAR-like JSON note is
withheld in full from newly derived PRIVATE workrooms, rather than
partially interpreted without the original request/response context.
The original privately retained source is never modified. New masking-cue
receipts are v19, with exact historical v1-v18 reopen support.
A source-free, printable PRIVATE-HAR-HOLD.html board identifies whole-copy
withheld markers by original ordinal inside a new separate masking-cue room
or the optional initial HUMAN preview. PRIVATE-HAR-INVENTORY.html and
PRIVATE-HAR-INVENTORY.csv also group literal masking markers by HAR source
category and original ordinal, never showing source text, URLs, paths,
client names or digests. Native v15 reopen compares these HTML and CSV bytes
as part of the original owner-private source-linked receipt.
New PRIVATE-HAR-QUEUE.html also provides fully offline, script-free links
from each HAR marker category to the complete original ordinal roster and
a distinct list of wholly withheld copies. Source names, paths, original
text, SHA values and human notes are excluded; marker counts do not
represent a proven privacy assessment. The PRIVATE-HAR-QUESTIONS.html
printable script-free checklist now supplies non-authorizing manual
questions by original ordinal and visible literal marker family.
Local checkboxes have no persistence, storage, export or decision effects.
The v17 native receipt binds the checklist and all existing source-free
cue files; earlier v1-v16 packages reopen under their historical bytes. A marker
may pre-exist in raw text; the board is only a navigation aid, not a verdict.
When a new derived note is wholly withheld, its initial private HUMAN
decision CSV and local browser editor start at SOURCE_OWNER_REQUIRED,
rather than implying that the derived source can be inspected directly.
The actual source owner may review and propose a different local stage;
all final outputs remain HOLD and no stage authorizes disclosure.
Independent HUMAN review of the original is mandatory; this is never
safe-sharing certification. No runtime scan or network.

### New: pasted command, HTTP exchange and structured credential masking

The original local PRIVATE note masker now withholds more credential-bearing
fields in pasted cURL shell flags and quoted HTTP headers, request/response
Cookie and token headers, structured JSON/YAML secrets, URL user-info,
path-session IDs and common session/token query fields, including
strictly percent-decoded known parameter names in copied URLs. This only affects
**new owner-private `notes.py prepare` workrooms**; original old HUMAN packets
are never silently rewritten. The result is still **pattern-based,
incomplete, confidential and not approved for external sharing**.

[Supported original PRIVATE source shapes, operator usage and explicit privacy
limits](PRIVATE-CREDENTIAL-MASKING.md).
The same guide documents the native `notes.py masking-cues` command:
a separate source-bound **offline HUMAN cue overview**, with original
ordinals and literal known placeholder families but no note content.
It does **not** establish redaction coverage, secrecy or public safety.
Use optional `notes.py prepare --with-mask-cues` to make a
source-minimal PRIVATE cue preview directly accessible inside a **NEW**
original workroom, without changing the default original finalization.
For separate exact original byte custody, use native `masking-cues`.

## What this does

The existing central `lightup.redaction.redact_text()` now includes the **unchanged original producer patch** from draft [PR #672](https://github.com/Zennay/Lightup/pull/672) for `Authorization: Basic ...` and `Proxy-Authorization: Basic ...`, alongside existing Bearer, AWS access key and generic token/password patterns. Original source-owner branch untouched. The utility **does not claim to detect all secrets, anonymize data, erase personal information, or make material safe to share**.

This independent, original-source-driven application:

1. Accepts **1–12 individually selected existing owner-private UTF-8 notes** (each at most 512 KiB; overall 2 MiB), without filesystem discovery. Symlink, special file, non-owner input, group/world-readable file, corrupt text and oversize source refuse with HOLD.
2. Invokes unchanged installed original `redact_text()` on the selected text only, without transmitting any bytes to a model, server, target or analytics platform.
3. Creates a **fresh private 0700 directory** outside the repository with owner-only 0600 credential-masked text files, readable scriptless local HTML summary, unsigned exact-source SHA/size manifest with only source ordinals (never source filenames), an original-source-bound editable HUMAN CSV, and an **offline interactive HUMAN browser editor** with a SHA-256 CSP-pinned inline script and no network/storage.
4. The browser lets an operator choose exactly one of `NEEDS_HUMAN_REVIEW`, `SOURCE_OWNER_REQUIRED`, `WITHHOLD`, or `INTERNAL_REVIEW_ONLY` for each original source and add a bounded brief internal note. It downloads a PRIVATE CSV locally. Even `INTERNAL_REVIEW_ONLY` never means external clearance.
5. A separate explicit `finalize` command reopens the unchanged original workroom, rejects edited source-bound SHA/byte metadata and replaced redacted note bytes, reads the complete original-bound HUMAN CSV, and creates a *second* fresh owner-private HUMAN packet with decisions, originals' **masked only** note copies, combined internal notes, static readable HTML, and unchanged literal-false authority flags.
6. The final stage deliberately returns **HOLD (code 3)** even when its local HUMAN packet was correctly written: there is **never** a release verdict, client consent or verified masking claim. Preparation returns **REVIEW_ONLY (code 2)**. Neither is a successful authorization code.

## Run locally

Requirements: Python 3.11+ and this LightUp checkout. No pip, service, credentials or network.

~~~sh
mkdir -m 700 -p /private/operator-lightup-work
chmod 600 /private/first-private-note.txt /private/second-private-note.txt

python3 private-assessment-notes/notes.py prepare \
  --source /private/first-private-note.txt \
  --source /private/second-private-note.txt \
  --private-parent /private/operator-lightup-work
~~~

Open the printed `OPEN-PRIVATE.html` locally, and follow the link to **PRIVATE offline interactive HUMAN decision editor**. Download the resulting PRIVATE decision CSV. Never put it on an open shared drive.

~~~sh
python3 private-assessment-notes/notes.py finalize \
  --original-kit /private/operator-lightup-work/PRIVATE-lightup-notes-<actual-id> \
  --decisions /private/operator-lightup-work/PRIVATE-HUMAN-decisions-completed.csv \
  --private-parent /private/operator-lightup-work
~~~

The second workroom offers `PRIVATE-HUMAN-summary.html`, individual and combined masked notes, unsigned original-source manifest and completed HUMAN decisions. **The browser/editor does not perform finalize, assessment or any automatic outward action.**

The source file content is never included in either output; **the redacted content may still be highly sensitive**. Original source hashes are not independent provenance or integrity signatures, and source identity cannot establish authorization.

### Workflow and release boundaries

- This is **PRIVATE internal triage only**. Do not post the masked output or manifest to a public issue, PR, Notion page, website, email, or unapproved recipient.
- Pattern redaction cannot prove absence of credentials, secrets, PII or proprietary client evidence; every original needs independent HUMAN privacy review.
- The original #672 fix is selectively composed, not merged to `main` or released. The original owner's production source and review remain separate.
- No QA/test suite added, modified or executed as part of this companion. Native Python syntax/build inspection and source inspection are the only checks made in this lane.
- Original exact-head hosted + permanently registered named VPS CI, original source-owner and independent privacy/security reviews, #177/#182/#829, authenticated separately current client/operator consent with action-time revocation, and explicit HUMAN GO remain release gates. No production merge/deploy.

## Source ownership

This lane is exclusively `private-assessment-notes/` plus the **exact original** `src/lightup/redaction.py` fix from [PR #672](https://github.com/Zennay/Lightup/pull/672). It does **not** alter the concurrently active [assessment-integrated-suite PR #1688](https://github.com/Zennay/Lightup/pull/1688), any active source-authority owner, assessment executor, domain state, auth policy, persistence, runner, CI, test path or third-party repo. The original author PR is not silently claimed as complete.

**CSV safety:** PRIVATE human notes beginning with a spreadsheet formula prefix
(`=`, `+`, `-`, or `@`, even after whitespace) are rejected in
both the browser export and native finalize. Do not open untrusted CSV with
spreadsheet macros or auto-link execution enabled.

## NEW: retain PRIVATE human decisions across offline revisions

A complete HUMAN decision packet can be reopened **without any original unmasked
source data** and without modifying the earlier packet. The source-bound stage
history and the exact locally masked content are preserved in a new exclusive
private directory. The original full HUMAN CSV receives its own unsigned SHA-256
digest on first `finalize`; reopening demands the original content digest and
HUMAN stage counters match before anything is prepared.

~~~sh
python3 private-assessment-notes/revision.py \
  --prior-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --private-parent /private/operator-lightup-work
~~~

The reopened package contains a fully offline browser Studio prefilled with the
prior human decisions, its own source-byte bound PRIVATE manifest, and the
unchanged redacted-only note bytes. A human can revise stages and notes in the
local browser, export another PRIVATE CSV and deliberately `finalize` another
separate packet. `revision_level` is capped at 32. Original packet and masked
bytes are never overwritten, and old HUMAN recommendations are not silently
carried into authorization or release. Manifest hashes are unsigned local
integrity identifiers only; they are not trusted producer signatures. The
reopen step always reports REVIEW_ONLY and finalization always remains HOLD.


## New PRIVATE human review board and selected internal discussion packets

The generated `PRIVATE-HUMAN-editor.html` now includes an in-page private
pattern-masked original note viewer (collapsed by default), local source-position
and note search, a stage filter, visible/all-source counters, and explicit
confirmed bulk HUMAN discussion stages with one-step undo. For safety, only
`NEEDS_HUMAN_REVIEW`, `SOURCE_OWNER_REQUIRED`, and `WITHHOLD` may be applied
in bulk: `INTERNAL_REVIEW_ONLY` must always be chosen individually. Filtering
never removes original source rows from the complete CSV; native finalize still
reopens and checks the complete original source-bound packet.

After completing and finalizing an original HUMAN packet, optionally assemble
a strictly **local selected-only internal discussion copy**. This is not a
customer/client handoff or permitted disclosure:

~~~sh
python3 private-assessment-notes/selective_handoff.py \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --position 1 --position 3 \
  --private-parent /private/operator-lightup-work
~~~

Only explicitly selected original positions currently marked
`INTERNAL_REVIEW_ONLY` are admitted. Other stages (including `WITHHOLD`)
cause a complete HOLD with no published output. The original complete HUMAN
CSV and manifest are re-admitted with unsigned exact-byte SHA binding and stage
counts before any selected output is created. A new owner-only 0700 directory
contains only the selected **masked** note bytes, scriptless selected-only
private summary HTML, a source-bound unsigned PRIVATE manifest, and a
selected-only discussion CSV. HUMAN free-text notes are withheld entirely;
no other source positions, original unmasked bytes or other HUMAN stages are
included in the selected packet.

The selected CSV is **not** a complete input for the native finalize stage.
The packet is never encrypted, recipient-authenticated, delivered or released;
its hash is not a signature. Masked text can retain secrets and personal
information. Independently verify the intended real recipient, channel,
actual consent, privacy, security and explicit HUMAN GO under the existing
original release process. This CLI intentionally exits HOLD (3) even when it
successfully wrote a private discussion copy.

The same selection is now also available through the **existing unified native
notes CLI**, without invoking an independent helper:

~~~sh
python3 private-assessment-notes/notes.py select \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --position 1 --position 3 \
  --private-parent /private/operator-lightup-work
~~~

Both entrypoints use exactly the same native fail-closed selection function.

## Resume a browser HUMAN draft without changing original sources

The offline browser editor can now reopen its own previously exported
`PRIVATE-HUMAN-decisions-completed.csv` before invoking native `finalize`.
Choose the local file in the **Resume PRIVATE draft** control. Import is
entirely local and capped at 64 KiB: exact header, UTF-8 bytes, all original
source ordinals and unsigned original-source digests in the same order, valid
HUMAN stages, permitted small note text and the full source count must match
first. Invalid, incomplete, noncanonical, reordered or mismatched files leave
**every current browser choice untouched**. A full match still requires
explicit human confirmation before overwriting local draft selections.

Only browser-produced complete canonical CSV drafts are accepted by that UI.
The separate native `finalize` remains the authoritative source-bound
PRIVATE step. Neither reopening a draft nor an unsigned SHA authenticates
its author, establishes a grant/consent or authorizes a recipient. No browser
storage, server transmission, network, scan or background submission occurs.

## Visual original-bound selected discussion plans

The offline original PRIVATE HUMAN editor now offers a per-source
**Plan internal-only discussion** checkbox (disabled unless that particular
source has been individually marked `INTERNAL_REVIEW_ONLY`). Stage changes
back to withholding, owner-required or unreviewed status automatically
clear and disable that source's checkbox. Filtering never selects or
excludes original rows by itself.

After saving the **complete** source-bound PRIVATE HUMAN decisions CSV,
click **Save selected PRIVATE discussion plan**. Confirm the selected count:
the browser downloads `PRIVATE-HUMAN-selected-plan.json` containing only
the original source count, selected original ordinal/unsigned original-byte
SHA pairs, strict false-authority flags and HOLD. It contains **no** original
text, redacted text, HUMAN free note or recipient identity. This is an
unsigned LOCAL reference plan, not a signature, source-owner authentication,
privacy clearance or permission to share.

**Required order:** native `prepare` → browser decisions CSV and separately
browser-selected JSON plan → native `finalize` for the **whole original
source set** → native `select --plan` on the completed owner-private packet.

Store the locally downloaded plan only inside your existing private work area,
and set its owner-only file mode before native selection. Browser download
permissions are not guaranteed to be 0600:

~~~sh
chmod 600 /private/operator-lightup-work/PRIVATE-HUMAN-selected-plan.json

python3 private-assessment-notes/notes.py select \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<actual-id> \
  --plan /private/operator-lightup-work/PRIVATE-HUMAN-selected-plan.json \
  --private-parent /private/operator-lightup-work
~~~

The native command accepts **either** `--plan` **or** one or more
`--position` arguments; never both. Native admission rejects unsafe or
non-owner plans, duplicate JSON keys, extra schema keys, any implied authority,
missing/reordered/mismatched original source identities, and any planned
source that the final original HUMAN decisions did not individually mark
`INTERNAL_REVIEW_ONLY`. No selected packet is written on an admission HOLD.
Accepted plans remain source-only references; the existing fresh 0700/0600
selected internal discussion packet is created locally and the command still
returns HOLD (3). It never uploads, sends, grants permission or publishes.

If you change a HUMAN stage after exporting a plan, export a new plan after
the whole-source CSV is updated; old plans cannot override the final original
HUMAN decision. The native completed-original SHA and stage accounting remain
mandatory even when a browser selection appears valid.

### Reopening a selected-only PRIVATE plan

The offline HUMAN browser editor can **also reopen** one of its own canonical
`PRIVATE-HUMAN-selected-plan.json` files using **Reopen original PRIVATE
selected discussion plan**. If you saved complete HUMAN CSV choices separately,
restore those choices first; the plan will not set any HUMAN stage or free note.

The plan restore requires exact canonical UTF-8 JSON format, the same complete
source count and original unsigned per-position SHA identities, distinct
strictly ascending original ordinals, literal false authority flags and all
selected sources currently individually marked `INTERNAL_REVIEW_ONLY`. It
refuses modified or malformed plans atomically, without replacing any current
checkbox selections. Even a matching plan requires a separate HUMAN
confirmation. It restores only the selected UI checkboxes, not original
evidence, external approval, real recipient identity, authorization or
revocation status. This is entirely in-memory/offline; no upload or storage.

## Source-exact PRIVATE HUMAN revision change report

After completing one original HUMAN packet, reopening it through the existing
native `revision.py` command, editing its local HUMAN CSV, and independently
**finalizing** that direct child revision, the native CLI can now produce an
operator-readable review of HUMAN changes between exactly those two packets:

~~~sh
python3 private-assessment-notes/notes.py changes \
  --earlier /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<parent-id> \
  --later /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<direct-revision-id> \
  --private-parent /private/operator-lightup-work
~~~

The CLI reopens **both** completed 0700/0600 original HUMAN packets, re-admits
the original redacted source bytes, manifest, every HUMAN CSV row and exact
original source identities. The newer packet must be an actual **direct
native revision**, with the previous exact original manifest and HUMAN CSV
unsigned SHA lineage and precisely one additional revision level. An unrelated
packet, modified original data, fabricated authority flag or missing/extra
source will HOLD **before** a report is created.

A fresh owner-only PRIVATE report directory contains an accessible scriptless
`OPEN-PRIVATE.html`, source-minimal `PRIVATE-HUMAN-changes.csv` and a
PRIVATE unsigned SHA-bound `PRIVATE-HUMAN-changes.json`. It shows exactly
which original *positions* had a HUMAN stage change and/or HUMAN note changed,
with the earlier/later stage names. Neither original unmasked content, masked
text, nor free-text HUMAN notes appear in any of these change outputs.
Unchanged original rows are counted, not disseminated. HUMAN note changes are
shown only as boolean `private_note_changed` values, never the note itself.

An unsigned local lineage digest does **not** verify the real human reviewer,
privacy clearance, client consent, remediation, absence of findings, or security
risk. This is only a PRIVATE HUMAN recommendation history. The command
deliberately exits HOLD (3), including after writing a valid private
history; it performs no scan, network, grant, communication or deployment.

## Complete PRIVATE HUMAN longitudinal history (2–16 finished revisions)

A local operator may now inspect **an entire explicitly selected consecutive
native HUMAN revision chain** without reproducing the original source material
or disseminating every PRIVATE note. Starting with two completed owner-private
packets and continuing with each directly completed native revision, pass the
paths in chronological order:

~~~sh
python3 private-assessment-notes/notes.py history \
  --packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<first-id> \
  --packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<second-id> \
  --packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<third-id> \
  --private-parent /private/operator-lightup-work
~~~

All selected packets must be completed original native HUMAN packets in private
0700 directories with intact 0600 manifests, original masked source bytes, and
complete original HUMAN decisions CSV. The native reader enforces sequential
`revision_level`, exact prior manifest and prior decisions SHA-256 references,
and an unchanged complete original source roster and pattern-masked bytes.
Any missing level, fork, reordered packet, edited HUMAN manifest or source
drift is a whole-chain HOLD before publishing the derived workspace. No
permission, human identity, redaction completeness or security authenticity is
inferred from these **unsigned** local digests.

The command creates a *new* exclusive owner-private workspace with:

- `OPEN-PRIVATE.html`: printable scriptless overview and source-position-only
  declared stage/note change history, current per-original HUMAN follow-up
  summary and confidential local file links.
- `PRIVATE-HUMAN-board.html`: **interactive, entirely offline** HUMAN history
  board. Filter by original source ordinal, current HUMAN status, or sources
  with declared changes; expand/collapse a given source's revision timeline.
  Browser JavaScript is pinned to its SHA-256 CSP and has no remote resources,
  fetch, upload or persistent browser storage.
- `PRIVATE-HUMAN-events.csv`: original position/revision/old and new HUMAN
  stage and note-changed BOOLEAN only, no PRIVATE note contents.
- `PRIVATE-HUMAN-current-review.csv`: per-original latest HUMAN stage,
  number of stage/note changes, last changed revision and whether an explicit
  HUMAN follow-up remains indicated.
- `PRIVATE-HUMAN-history.json`: PRIVATE unsigned original packet digest
  lineage plus source-minimal HUMAN stage/event summary, all authority flags
  false.

All CSV/HTML exports omit original source filenames, SHA identities, text,
masked text and free-text HUMAN notes. The JSON includes **unsigned hashes of
the original PRIVATE packet manifests/CSV** and must remain owner-private.
Never treat an unchanged stage as verified remediation, a changed note as
investigation evidence, or `INTERNAL_REVIEW_ONLY` as consent to share.
Nothing is sent, granted, scanned or scheduled. This is a HUMAN planning
product only; it deliberately returns HOLD (3) after generating the new local
workspace, preserving the original release gates and preventing accidental
success-as-authorization.

### Visual HUMAN follow-up grouping (offline only)

In the source-minimal `PRIVATE-HUMAN-board.html`, the **Local presentation
order** control can arrange the same original source cards by original ordinal,
by *already-declared* HUMAN stage, or by count of declared HUMAN changes.
This is **only a temporary on-screen arrangement**: it never rewrites source
ordinals, native decisions, historical packet order, underlying files or CSVs.
The stage grouping uses `WITHHOLD`, `SOURCE_OWNER_REQUIRED`,
`NEEDS_HUMAN_REVIEW`, then `INTERNAL_REVIEW_ONLY` for easier local HUMAN
discussion; it is explicitly not a risk score, urgency claim, security verdict,
assignment, consent, or notification. All original entries remain included in
the unchanged source-bound outputs irrespective of visual filters or sorting.

## NEW: original-bound PRIVATE HUMAN discussion agenda, offline round trip

The completed `notes.py history` workflow now has a separately admitted,
original-bound follow-up conversation planner. Its purpose is **local HUMAN
proposals only** — not a task assignment, real client contact, notification,
deadline, review clearance, privacy verification, security verdict or consent.

**1. Prepare an editable PRIVATE HUMAN agenda** from one existing completed
2–16-revision history workroom and the **actual last completed original
HUMAN packet**:

~~~sh
python3 private-assessment-notes/notes.py agenda \
  --history-kit /private/operator-lightup-work/PRIVATE-lightup-human-history-<id> \
  --latest-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<last-id> \
  --private-parent /private/operator-lightup-work
~~~

The native original reader admits the owner-only 0600 history JSON as **one
exact byte snapshot**, rejecting duplicate object keys, unexpected authority
claims or malformed source positions. It independently reopens the latest
original completed HUMAN packet, comparing original manifest and complete
HUMAN decisions SHA-256, exact original source count, ordinals and HUMAN stages,
and ensuring false-authority fields are literal booleans. This unsigned chain
is local byte binding, **not** source-owner authentication.

A new exclusive 0700 folder contains `OPEN-PRIVATE.html`, the fully
offline `PRIVATE-HUMAN-agenda-editor.html` with SHA-256 CSP-bound JavaScript,
a complete source-bound `PRIVATE-HUMAN-agenda-template.csv`, and
`PRIVATE-agenda-bindings.json`. The local editor shows only original
ordinal and last declared HUMAN stage. All original source text, credentials,
masked evidence and free-text notes are intentionally absent.

For every original position, a human may propose **no action**, a private
discussion, asking an original source owner, or withholding the topic from
discussion. A proposed HUMAN team is a bounded suggestion only (Unassigned,
Security, Privacy, Client operations, Platform); an optional calendar day is
manually proposed, never scheduled; an optional short PRIVATE question is
entered locally. There is no contact data, real identity verification or
network activity. Nothing is inferred automatically as an actual task.

The browser can save the **complete** original source-bound PRIVATE CSV,
including all hidden/unchanged source rows, and later reopen an intact original
browser-exported draft after validating **every** source ordinal, original
HUMAN stage, unsigned history digest, allowed field and completeness. Any
mismatch leaves all existing local choices intact. Restoring a draft never
approves or schedules anything.

**2. Finalize the HUMAN discussion proposal locally, not the assessment.**
Put the completed CSV in the owner-private work area and set it to mode 0600;
browser downloads alone do not guarantee private file permissions.

~~~sh
chmod 600 /private/operator-lightup-work/PRIVATE-HUMAN-agenda-completed.csv

python3 private-assessment-notes/notes.py agenda-finalize \
  --agenda-kit /private/operator-lightup-work/PRIVATE-lightup-human-agenda-<id> \
  --history-kit /private/operator-lightup-work/PRIVATE-lightup-human-history-<id> \
  --latest-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<last-id> \
  --completed-csv /private/operator-lightup-work/PRIVATE-HUMAN-agenda-completed.csv \
  --private-parent /private/operator-lightup-work
~~~

Native finalization independently re-admits the history and original final
completed packet **again**, checks the unchanged original agenda template and
all bound metadata, and validates the **entire** completed 1–12-source HUMAN
CSV in exact original order. The selected HUMAN action, team, optional real
ISO date format and short PRIVATE question cannot contradict the original
identity, impersonate consent or turn a `NO_PROPOSAL` row into a hidden
assignment. Formula-like note prefixes are refused. The native operation
writes a **different** new 0700/0600 owner-private review packet with
scriptless readable `OPEN-PRIVATE.html`, a completed all-original-rows
PRIVATE CSV and source-bound JSON holding **only explicitly proposed**
discussion rows.

Only this new private output contains the manually written PRIVATE questions;
neither web uploads, email, calendar, worker dispatch, source scanning, consent
grants nor real client/operator interaction occur. All outputs remain local
and confidential. The prepare stage returns REVIEW_ONLY (2), and the native
finalization returns HOLD (3), **even when the local proposal was created
successfully**. All original main-merge, CI, source-owner, security/privacy,
current separately authenticated client/operator consent, action-time
revocation and explicit HUMAN GO gates remain mandatory.

## Team-minimal PRIVATE HUMAN discussion excerpt (never delivery)

After preparing a complete and source-bound **local HUMAN agenda review**, an
operator may deliberately generate an additional separate **single-team**
PRIVATE conversation excerpt for one manually proposed team label. The
full original agenda, original completed HUMAN packet and history remain
unchanged. There is **no recipient authentication** and no automatic transfer.

~~~sh
python3 private-assessment-notes/notes.py agenda-team \
  --review-kit /private/operator-lightup-work/PRIVATE-lightup-human-agenda-review-<id> \
  --history-kit /private/operator-lightup-work/PRIVATE-lightup-human-history-<id> \
  --latest-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<last-id> \
  --team PRIVACY \
  --private-parent /private/operator-lightup-work
~~~

`--team` is one of `SECURITY`, `PRIVACY`, `CLIENT_OPERATIONS`, or
`PLATFORM`. The native path **reopens the complete original final HUMAN
review packet, all original source-bound history identities, and the complete
PRIVATE review CSV** before selecting only original human proposals
explicitly labelled for the requested team. Non-selected teams' questions,
dates, contents, names and source positions are entirely excluded from
the resulting team HTML, CSV and JSON. Empty-team selection returns HOLD
without creating a packet.

The output lives in a new owner-private 0700 directory, with private 0600
`OPEN-PRIVATE.html`, `PRIVATE-HUMAN-team-brief.csv`, and
`PRIVATE-HUMAN-team-brief.json`. These contain only the selected team's
original source ordinals, last HUMAN stage, manual discussion category, proposed
day and original HUMAN question. The JSON binds the source privately through
unsigned local artifact SHA-256 values, **not** signatures or proof of an
authenticated team member.

**Important:** the `--team` label is an unauthenticated suggestion, not a
verified recipient, validated group membership, accepted client request,
actual assignment, calendar booking, permission to disclose, security verdict,
or communication channel. Do not publish or transmit the PRIVATE result
without genuine independent recipient verification, current security/privacy
approval, separate live client/operator consent, action-time revocation and
explicit HUMAN GO. No network, email, notification, task dispatch, scan or
authorization action occurs. The operation returns HOLD (3), including on a
successfully created local private packet.

## PRIVATE credential-masking improvements and manual second pass

Original source admission in this self-contained notes workroom now **layers**
`private_masking.mask_private_notes()` over the existing unchanged original
`lightup.redaction.redact_text()` producer. The additional **bounded local
heuristics** mask commonly missed literal credential **shapes**: URL user-info
(`protocol://user:password@`), token-bearing URL query/fragment values,
Cookie/Set-Cookie and common authorization/custom auth headers, JSON-quoted
password/client-secret/access-token members, upper-case environment secrets,
common private-key PEM blocks, JWT-shaped values and selected known provider
token shapes. This is only extra local pattern masking: **never a promise of
complete credential removal, PII anonymization, safe publication, or privacy
clearance**. Previously created packets are not silently rewritten; new
`notes.py prepare` operations use the enhanced masking.

### Credential-field name obfuscation in pasted cURL payloads

The local cURL form masker canonicalises field names only before matching known credential labels. It recognises percent-encoded ASCII letters/digits/underscore/hyphen (for example, pass%77ord), Unicode compatibility spellings (such as full-width Latin letters), and embedded Unicode format controls (such as zero-width characters). The displayed original key spelling is retained for HUMAN context while the associated value is replaced. Payload values are never percent-decoded, and this narrow heuristic does not parse or execute shell/URI syntax.

This closes known obfuscation gaps for a bounded set of credential names; it is not complete redaction, secret detection, anonymisation or permission to share. Unknown keys, malformed payloads and irregular encodings remain PRIVATE/HOLD and require independent HUMAN review.

### URL query-name obfuscation in PRIVATE note copies

The local URL query masker also canonicalises parameter names before comparing them with its bounded credential-name list. It recognises Unicode compatibility spellings (for example, full-width Latin letters) and ignores embedded Unicode format controls during matching, while preserving the original key spelling and withholding only the associated value. Percent-encoded names continue to be decoded locally for matching only; payload values are not decoded. Query scanning remains bounded and heuristic, never a complete URL parser or privacy PASS.

### Manually mask remaining sensitive text without changing original packets

The operator can also request a **second, explicitly HUMAN-directed literal
masking pass** on a source-bound, *completed* original PRIVATE HUMAN packet.
This is useful when remaining names, private identifiers or unknown credential
formats survive first-pass heuristic masking, and the original packet must
remain immutable for review provenance.

**1. Prepare an original-bound editable PRIVATE rule template.**

~~~sh
python3 private-assessment-notes/notes.py mask-template \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<id> \
  --private-parent /private/operator-lightup-work
~~~

The command independently reopens the full native completed original packet,
with its original masked notes, COMPLETE original HUMAN CSV and unsigned
manifest SHA bindings. It creates a fresh owner-only 0700 folder containing
`OPEN-PRIVATE.html` and owner-only 0600
`PRIVATE-manual-mask-rules.json`. The JSON initially contains a blank
`literal_to_mask` for each real original source position plus exact original
SHA identities. No secret text is included in the blank template.

**2. Fill in chosen literals and remove unwanted original entries.**

Edit the template locally. For every selected original note, replace the
empty `literal_to_mask` value with the exact UTF-8 phrase (3–256 characters)
to redact; delete unused entries. To mask multiple separate phrases in the
same original source, duplicate that source's JSON rule entry and set its
`literal_to_mask` accordingly. Do NOT alter the original source ordinal,
SHA identities, false-authority fields, or completed HUMAN manifest/CSV
digests. The edited JSON **contains the actual sensitive literals**;
keep it owner-only mode 0600, out of git, Notion, public systems, emails,
screenshots and other shared services. The rules file is deliberately never
copied to the output.

**3. Create a NEW selected-only extra-masked PRIVATE packet.**

~~~sh
python3 private-assessment-notes/notes.py mask-copy \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<id> \
  --rules-json /private/operator-lightup-work/PRIVATE-lightup-mask-plan-<id>/PRIVATE-manual-mask-rules.json \
  --private-parent /private/operator-lightup-work
~~~

`mask-copy` admits only owner-private original files, one complete already
finalized original HUMAN packet, its exact original manifest + complete HUMAN
CSV and 1–24 bounded original-source-matched HUMAN literal rules. Every
original selected phrase must be present in the ALREADY masked note and every
requested occurrence must be masked without intersecting another rule.
Invalid original SHA, unmatched phrase, duplicate JSON key, overlapping match
or fabricated authority field returns HOLD without creating an output packet.
Rule text is never printed, persisted in the output, or sent.

The output is a **separate** exclusive owner-private 0700 directory containing
only explicitly selected additional masked originals, each in owner-only 0600
files, a readable local scriptless `OPEN-PRIVATE.html` and
`PRIVATE-extra-mask-bindings.json` with original source/decisions SHA
references, replaced-occurrence counts and unsigned output digests.
Original PRIVATE HUMAN free-text notes, raw literal rules, and unselected
source notes are withheld. Neither previously completed HUMAN decisions nor
original source files are modified. This selected derivative is NOT a new
valid native original completed packet and cannot be substituted as one to
bypass lineage or release checks.

**Always HOLD:** no model, network, scan, actual client/customer evidence,
authentication, grant, communication, signature, implicit team assignment,
recipient verification, or public sharing. New manual template returns
REVIEW_ONLY (2); `mask-copy` returns HOLD (3) even after correctly writing
the selected-only private local result. All original independent source-owner,
security/privacy reviews, CI, client/operator separate active consent,
action-time revocation and explicit HUMAN GO remain mandatory.

### Offline guided source-by-source manual masking editor

The native `mask-template` command now also generates
`PRIVATE-manual-mask-editor.html`, linked from the private
`OPEN-PRIVATE.html` workroom. This is a SHA-256-CSP-pinned **fully offline**
HUMAN interface: expand only the pattern-masked original you want to review,
click **Add original-specific PRIVATE literal**, type the exact remaining
sensitive phrase, add/remove up to 24 original-source-bound rules, and
explicitly export `PRIVATE-manual-mask-rules-completed.json`.

All original SHA identities and exact completed HUMAN manifest/CSV digests
come from the completed packet, not a user-supplied claim. The interface
contains the already-pattern-masked PRIVATE source text (which can still
contain real secrets), and the typed literal is itself SECRET, so never put
the HTML or downloaded JSON on a shared drive or in a pull request. It has no
network, persistence, upload, model or external recipient. The operator
must immediately move the downloaded JSON to an ordinary owner-only 0600
private file, then explicitly invoke `notes.py mask-copy`. A browser
download alone does **not** enforce the 0600 filesystem requirement.

The original blank `PRIVATE-manual-mask-rules.json` remains available for
manual text editing without JavaScript; its empty placeholders must be filled
or removed before native processing. `mask-copy` still rejects all unsafe,
overlapping, stale, unmatched, ambiguous or unauthorized inputs.

### Reopen an unfinished manual-masking request, without retyping secrets

The fully offline masking board now also supports **Reopen original locally
exported PRIVATE masking rules (.json)**. It accepts only its OWN canonical
complete browser-exported JSON (up to 64 KiB), with the exact previously
completed original packet manifest SHA, original complete HUMAN decisions SHA,
source positions, source SHA identities, source-by-source short literal rules
and all false-authority fields intact. It first validates every row and
requires a separate HUMAN confirmation, then replaces only the unsaved local
browser editor fields. On any mismatch or cancellation, the current unsaved
fields remain intact. The native `mask-copy` command still independently
reopens the original completed source packet; a browser resume is **not**
trusted source, verified masking, file authorization or consent. Imported and
exported rule JSON contains original sensitive literal strings and must remain
owner-private; never upload or share it.

## Complete PRIVATE HUMAN sensitivity triage (offline)

The original completed credential-masked HUMAN note packet now also supports three integrated native `notes.py` commands: `sensitivity-prepare` for a complete exact-original-source-bound owner-private concern template plus offline browser editor, `sensitivity-finalize` for a fresh source- and HUMAN-decision-byte-bound PRIVATE review/receipt, and `sensitivity-focus` for a minimum-necessary private HUMAN agenda for **one explicitly chosen** possible sensitivity category and one original HUMAN review status. Original source text is never copied into these triage and agenda artifacts; source identifiers and HUMAN notes remain owner-private. Browser drafts can be resumed locally only after full original byte-identity and row/category validation, without changes on mismatch. All routes deliberately remain REVIEW_ONLY/HOLD and never grant privacy clearance, source authenticity, real consent, recipients, permissions, disclosure or assessment execution.

[Open the complete sensitivity triage & exact-source HUMAN follow-up operator guide](PRIVATE-SENSITIVITY-TRIAGE.md). This extends only the existing separate DRAFT/HOLD assessment-notes workroom. Mandatory original source-owner/security/privacy/browser review, exact-head hosted/named VPS CI, current separately authenticated client/operator consent with action-time revocation and explicit HUMAN GO are untouched.


## Source-bound PRIVATE HUMAN sensitivity continuity

The existing private HUMAN sensitivity workflow now includes **`notes.py sensitivity-history`**, a genuinely offline original-bound 2–8 completed HUMAN review chronology. Each round is admitted against the original completed masked-note packet, complete original HUMAN CSV, original source byte SHA manifest, exact round CSV digest, status/topic counts and literal-false authority fields. Repeated paths or an original source mismatch refuse the entire history; separate byte-identical HUMAN decision submissions are allowed but explicitly recorded as duplicate content, never independently authenticated opinions or validated progress.

The local owner-private workspace provides an interactive CSP hash-pinned `PRIVATE-HUMAN-timeline.html`, printable scriptless full change history, full original-position change CSV, private per-round aggregate counts, unsigned source-bound receipts and the previous full private HUMAN CSV. Its browser does not embed source bytes, SHA identifiers, original filenames or human free-note content.

The same kit also includes a brand-new blank exact-original-bound sensitivity editor/template, so an operator can intentionally prepare the next review round with the **existing** `sensitivity-finalize` command. Nothing implicitly carries forward a supposed privacy clearance. An optional explicit restore of the previous CSV requires original-source matching and HUMAN confirmation.

[Full source-bound sensitivity history and next-round instructions](PRIVATE-SENSITIVITY-TRIAGE.md). All locally generated private materials remain HOLD/REVIEW_ONLY; neither a changed HUMAN label nor a reduced concern count verifies masking, effective remediation, consent, identity, recipient clearance or permission to release.


## Private HUMAN attention-only handoffs from changing original reviews

The native `notes.py sensitivity-attention` command is an additional complete offline HUMAN follow-up journey. Supply the exact original completed owner-private note packet, two distinct original completed sensitivity review packets in declared earlier/later order, a required human-only selection mode (`ALL_ATTENTION`, `CHANGES_ONLY`, or `CURRENT_WITHHOLD`) and optionally one category from the later round. The tool independently re-admits the original source-byte identity and both original complete HUMAN review CSV/receipt pairs, and creates **a new 0700/0600, minimum-necessary original-position-only PRIVATE conversation board**, separate selected CSV and source-bound unsigned receipt. Nothing is automatically assigned, sent, published, granted or declared fixed; the complete HUMAN note text and source text are withheld.

The combined follow-up continuity is: `sensitivity-prepare` → `sensitivity-finalize` → another HUMAN review / `sensitivity-history` → `sensitivity-attention` for selected private discussion. [Operator commands and release boundaries](PRIVATE-SENSITIVITY-TRIAGE.md). The workflow remains PLAN/LAB ONLY DRAFT/HOLD and preserves all original exact-head CI, source-owner, independent privacy/security/browser, separate current authenticated consent/revocation and explicit HUMAN GO gates.


## Complete PRIVATE multi-reviewer HUMAN sensitivity reconciliation

`notes.py sensitivity-reconcile` admits **2–8 original completed, source-exact owner-private HUMAN sensitivity review packets**, refuses duplicate directory selections and explicitly records byte-identical HUMAN reviewer decision pairs without treating them as authenticated independent reviewers, then builds an offline PRIVATE reviewer-disagreement and discussion workroom without changing original owner code. The integrated browser Studio shows per-original HUMAN stage/category proposals side by side, flags literal disagreements and WITHHOLD items, and offers independent per-source manual next-round decisions and source-bound full CSV export. No automatic consensus adoption, prior HUMAN note-text copying, real reviewer identity verification or external data transfer.

The new kit is natively compatible with **the unchanged original `notes.py sensitivity-finalize`**: it contains a fresh canonical original-bound `PRIVATE-triage-bindings.json`, complete default PENDING/UNKNOWN template and offline HUMAN editor. Finalization must independently re-admit the original source and the complete HUMAN CSV; all results remain HOLD/PRIVATE. [Operator guide, complete commands, artifact list and release limits](PRIVATE-SENSITIVITY-TRIAGE.md).


## Unified offline PRIVATE assessment sensitivity workbench

The official `notes.py sensitivity-workbench` subcommand now creates an integrated original-bound owner-private offline workspace instead of making an operator manually join multiple local HUMAN reports. Explicit `--mode timeline` assembles **2–8 manually ordered completed HUMAN rounds** into the interactive offline timeline, printable difference summary, complete original-position transitions, PRIVATE per-round counts, unsigned original custody receipt and a blank source-bound next-review Studio. Explicit `--mode reviewers` assembles **2–8 manually supplied HUMAN reviewer submissions** into a complete offline original-position reviewer comparison and next independent HUMAN proposal editor, scriptless discussion summary, bounded categorical matrix and PRIVATE counts/signals.

Both options invoke the already-installed original completed-source/round admission, refuse mismatched or duplicate **directory paths**, and explicitly report identical HUMAN decision CSV **content** as no proof of independently authenticated authors or chronology. They create one NEW 0700 owner directory with 0600 files, without copying original/masked source text into exported browsers and without sending anything. The timeline mode has one separately labelled PRIVATE last-completed human-decision CSV, which **may contain PRIVATE human note text** and must stay owner-private. Each new workbench includes the original-bound blank source manifest/template/editor, so the **unchanged** `sensitivity-finalize` may be explicitly invoked after a new complete HUMAN CSV export and owner-only file custody.

**Fixed persisted review compatibility:** the native sensitivity finalizer now records SHA-256 of its **actual canonical stored HUMAN CSV bytes**, not the independently parsed browser-upload bytes. Previously written packages with nonmatching receipt/file digest are intentionally **not** silently migrated or accepted. Re-finalize from unchanged original PRIVATE source + original triage kit + complete source-bound HUMAN decision CSV into a *new* PRIVATE packet; never replace original evidence or relax downstream validation.

[Complete operator commands, source/custody precautions and workbench walkthrough](PRIVATE-SENSITIVITY-TRIAGE.md). This is a PRIVATE, HUMAN-only, DRAFT/HOLD capability—not security attestation, consent, clearance, verified risk reduction, network authorization, assessment execution or production release. All mandatory exact-head CI, source-owner/security/privacy/browser approvals, scope issues, separately current authenticated client/operator consent incl. action-time revocation and explicit HUMAN GO remain intact.


## PRIVATE HUMAN disagreement navigation and focused handoff

The source-bound offline reviewer comparison Studio now highlights **note-only differences** as first-class HUMAN disagreement signals (status, categories and note-content-changed flags), with no private note text/hash embedded or published. A local focus menu filters original source slots by any HUMAN disagreement, private-note-only disagreement, declared WITHHOLD, declared REVIEW_REQUIRED or literally matching human labels/notes. Each filter is purely visual; **every** original source remains in the exported complete source-bound next-human-decision CSV.

The combined PRIVATE `sensitivity-workbench --mode timeline|reviewers` also produces a scriptless, selected-original-only `PRIVATE-HUMAN-attention.html` human discussion agenda in both modes. Reviewer mode additionally limits `PRIVATE-HUMAN-compact.csv` to source positions needing review, with explicit boolean WITHHOLD/REVIEW_REQUIRED and confidential-note-difference indicators. Complete original matrices/receipts and the unmodified original native finalizer remain distinct and strict. No prior free-text human notes, raw originals or scanned target content are included in the attention-only view. These remain owner-private HUMAN prompts, not recipient-authorized releases, scope grants, consent, independently verified remediation or a security PASS.

[Full instructions and artifact custody caveats](PRIVATE-SENSITIVITY-TRIAGE.md).


### PRIVATE reviewer Studio: two explicit output purposes

The offline multi-reviewer comparison now has an additional, local **selected-discussion CSV** button. HUMAN-only visibility filters can select note-content-only disagreements, declared WITHHOLD/REVIEW_REQUIRED, general disagreements or literal agreement and optionally original ordinals; that button saves only the *visible original ordinals plus bounded Boolean HUMAN disagreement/attention flags*. No source SHA, source note, HUMAN free-note text, filenames or recipient identity is included. This small **owner-private** conversation packet is not publishable and is **not accepted as a completed review**.

The original full **PRIVATE HUMAN decisions** export remains a separate action: it deliberately includes every original source and source-binding SHA and must pass unchanged native `sensitivity-finalize` after the operator moves it into a 0600 owner-only location. Neither export authenticates HUMANS, grants client consent, validates masking or clears release. [Commands and private custody steps](PRIVATE-SENSITIVITY-TRIAGE.md).


## Native PRIVATE selected HUMAN discussion receive (new)

The source-minimal CSV exported from the reviewer Studio is now a usable **native
PRIVATE HUMAN handoff** rather than a standalone, unbound download. The
`sensitivity-discussion-receive` command reopens the original completed
owner-private packet and **every original** 2–8 completed HUMAN sensitivity
review, reads the browser-selected CSV as an ordinary 0600 owner file, and
compares every selected Boolean against the ORIGINAL reviewer values. Invalid,
reordered, duplicated, noncanonical, incomplete, outside-source or stale
selections are rejected before creating a new room. No guess based on just a
CSV row, and no interpretation of literal agreement as verified safety.

~~~sh
# FIRST: export PRIVATE-HUMAN-selected-discussion.csv from the offline
# original reviewer Studio and move it into an owner-private 0700 folder.
chmod 600 /private/operator-lightup-work/PRIVATE-HUMAN-selected-discussion.csv
python3 private-assessment-notes/notes.py sensitivity-discussion-receive \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<id> \
  --review /private/operator-lightup-work/PRIVATE-sensitivity-review-<first> \
  --review /private/operator-lightup-work/PRIVATE-sensitivity-review-<second> \
  --selected-csv /private/operator-lightup-work/PRIVATE-HUMAN-selected-discussion.csv \
  --private-parent /private/operator-lightup-work
~~~

The command makes a **fresh 0700 directory** with a local scriptless printable
selected-only ordinal/Boolean conversation agenda, the exactly admitted 0600
selected CSV, an **unsigned PRIVATE original-source and original-human-review
receipt**, and a start page. It returns **HOLD (exit 3) even after writing**:
the output is never a completed original sensitivity review, authenticated
reviewer or recipient, consent, data minimisation certification, privacy
clearance, grant, delivery, fix proof or permission to share. Neither original
source bytes nor prior private HUMAN note contents are copied to the agenda.
Original source/decisions/reviewer hashes only appear in the owner-private
receipt; hashes are not cryptographic signatures or authentic identities.

**Always use the exact original reviewer packets in the same manually chosen
order as the Studio that made the CSV.** A selected-only CSV is deliberately
not an alternative to the COMPLETE original source-bound CSV accepted by the
unchanged native `sensitivity-finalize`. No network or real assessment is run.


### Reopen the ORIGINAL received PRIVATE HUMAN discussion, read-only

A later operator can now re-admit a previously produced discussion room
without importing trust from the room itself. The native reader independently
re-opens the same original completed owner packet and all 2–8 ORIGINAL HUMAN
review packets in the same manual order, compares selected Boolean values,
then demands **byte-identical canonical owner-private receipt, discussion HTML
and opening page**. Missing, altered, stale or swapped files cause HOLD. This
is a read-only custody/reopening feature, not a QA approval, authenticated
identity, replacement for the full original HUMAN decisions or consent.

~~~sh
python3 private-assessment-notes/notes.py sensitivity-discussion-reopen \
  --completed-packet /private/operator-lightup-work/PRIVATE-lightup-human-handoff-<id> \
  --review /private/operator-lightup-work/PRIVATE-sensitivity-review-<first> \
  --review /private/operator-lightup-work/PRIVATE-sensitivity-review-<second> \
  --room /private/operator-lightup-work/PRIVATE-lightup-human-discussion-<id>
~~~

The output deliberately remains **HOLD (exit 3)** even for a complete intact
reopening. A SHA digest or matching browser export never proves that the
original HUMAN reviewers are different, that original sources were authentic,
or that anyone can send, disclose or assess anything. All original review,
CI, security/privacy, current independently authenticated client/operator
consent, action-time revocation and HUMAN GO gates remain unchanged.


## Complete PRIVATE HUMAN selected discussion action workflow

The original selected-review browser export now has a source-bound native receipt,
read-only reopening, a local offline next-action Studio with ordinal-only concern
reasons and safe complete-draft resume, strict HUMAN action finalization and
read-only original-bound action reopener. No automatic consensus, authentic
reviewer identities, disclosure rights or release claims.

[Full step-by-step offline PRIVATE HUMAN action workroom instructions](PRIVATE-DISCUSSION-ACTIONS.md).


## PRIVATE HUMAN team conversation planning from original completed actions

The original source-bound PRIVATE HUMAN action chronology now supports a
complete separate local proposed-team discussion Studio and strictly admitted
HUMAN CSV finalization. Every original selected source remains present, starts
UNASSIGNED, and can be manually proposed for SECURITY/PRIVACY/CLIENT_OPERATIONS/
PLATFORM human conversation without making a real assignment, grant or send.
The resulting receipt, private full CSV and text-minimal printable team board
are separate from the original full HUMAN reviews and always HOLD.

[Complete source-bound offline HUMAN team routing instructions](PRIVATE-DISCUSSION-TEAM-ROUTING.md).

### Print-only PRIVATE HAR HUMAN source agenda (desk schema v2)

`notes.py har-review-progress` and `notes.py har-review-desk` now emit a
separate **`PRINT-PRIVATE-HAR-HUMAN-AGENDA.html`** in every new immutable
PRIVATE HAR next-action desk. Open it locally from the desk home page and
print an original-position-only checklist. It includes all 1–12 original
positions, operator-declared manual round count, generic next-action label,
manual outstanding-action count and unsigned paper checkboxes. It does **not**
contain the underlying HAR, note text, URLs, source filenames, hashes, source
identities or credentials. All status and priority labels are self-reported
HUMAN coordination, **not** security severity or an authorization verdict.

The unchanged `har-review-desk-reopen --workflow-room ... --progress-room ...
--desk-room ...` command now readmits the exact agenda bytes and its v2
unsigned receipt hash alongside all existing desk files. Older schema-v1
PRIVATE desks remain read-only reopenable using their original exact output
algorithm; they did not include a print agenda. This local print page can
still carry PRIVATE operational metadata: do not send or publish without an
independent HUMAN privacy review, current separate consent and release GO.


### Conservative handling of ambiguous encoded field names

Malformed percent escapes, invalid-UTF-8 URL keys, and query/form field names that remain percent-encoded after the bounded decode budget now have their associated values withheld. Original key text and delimiters remain intact; values are never decoded. Benign fields can be overmasked deliberately, so a placeholder is not a credential classification or clearance claim. Derived notes remain PRIVATE/HOLD.
