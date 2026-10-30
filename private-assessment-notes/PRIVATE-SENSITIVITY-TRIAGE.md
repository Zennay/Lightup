# PRIVATE HUMAN sensitivity triage for completed LightUp note packets

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a working **offline, owner-private, non-authorizing product**. It is NOT a privacy assessment, a clearance, a source authentication, a real client/operator consent check, a security finding, a grant or permission to share. No scan, active target, connection, model, upload, external distribution or automatic action.

## Purpose
Pattern-masked notes can still contain passwords, personal information, customer identifiers, proprietary data and context-sensitive secrets. This tool adds an independent **complete HUMAN sensitivity concern register** for an already-finalized original LightUp masked-note packet without copying any original or masked note text into the triage workroom. Every source stays identified by its original 1–12 ordinal and unsigned original SHA-256; no filenames or original note content are embedded.

## Offline operator journey

First complete the original `notes.py prepare` and `notes.py finalize` flow. Its already-completed HUMAN packet must retain its original 0700 owner-private folder, 0600 notes, original-source byte manifest, and original final decisions CSV.

```sh
python3 private-assessment-notes/notes.py sensitivity-prepare \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --private-parent /private/owner
```

### Optional integrated original masking-cue navigation

For a completed original HUMAN packet, prepare an additional **source-bound
PRIVATE cue navigator in the SAME sensitivity workroom**, without modifying
the original packet or any existing HUMAN decisions:

```sh
python3 private-assessment-notes/notes.py sensitivity-prepare \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --private-parent /private/owner --with-mask-cues
```

The optional new 0700 workroom includes three 0600 files:
`PRIVATE-masking-cues.html` (script-free category and original-ordinal links),
`PRIVATE-masking-cues.csv` (complete original marker-count roster), and
`PRIVATE-masking-cues-receipt.json` (original-source-bound unsigned HOLD
receipt). `OPEN-PRIVATE.html` links directly to this navigator and to the
unchanged sensitivity workflow. No original note bytes or source hashes
appear in the navigator. Literal placeholder counts do **not** establish
secret masking completeness or safe sharing.

The opt-in source-bound sensitivity **draft** uses schema v2, recording that
the exact cue receipt is required. On `sensitivity-finalize`, the native
finalizer independently reopens the original prepared notes and rejects a
missing, modified or substituted cue HTML, CSV or receipt **before** admitting
the completed HUMAN sensitivity CSV. Legacy non-opt-in v1 draft workrooms
retain their original behavior and do not require these files. The final
HUMAN packet remains PRIVATE/HOLD; opt-in cue receipt authentication is not
client authentication, security/privacy clearance or authorization.

To independently reopen only the cue desk from this optional joint workroom:

```sh
python3 private-assessment-notes/notes.py masking-cues-reopen \
  --original-kit /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --room /private/owner/PRIVATE-lightup-sensitivity-draft-ACTUAL
```

The separate cue reopening always returns HOLD and never changes the original
source or sensitivity decisions.

Cue schema v8 includes the named multipart postData marker where recognized.
All v1–v7 original private cue rooms remain read-only byte-reopenable,
and no marker family is a privacy release/verdict.

The optional original PRIVATE browser sensitivity editor also shows those
source-bound original-ordinal cue **counts inline** (never the original source
text or notes). Its local filter can restrict the visible table to any one
literal marker category or to positions containing any recognized marker.
The complete original-source HUMAN CSV export **always includes all rows**,
including hidden and unchanged sources. An independent explicit HUMAN
confirmation can mark only currently VISIBLE rows `REVIEW_REQUIRED` for
local discussion: never `WITHHOLD`, cleared, approved, remediated or
authentic. It does not dispatch or finalize anything. Filtering zero markers
does **not** mean that the source is safe, anonymous or free of secrets.


This creates a **new** `PRIVATE-lightup-sensitivity-draft-*` owner-only directory, with:

- `OPEN-PRIVATE.html`: readable human-only original-slot concern preview, not a source-text viewer.
- `PRIVATE-HUMAN-sensitivity-editor.html`: fully offline, accessible browser editor with CSP hash-pinned script and `connect-src 'none'`; no local/session storage or remote libraries. The operator can choose HUMAN concern statuses per ordinal, identify potential sensitive categories, and enter a short private follow-up question. Download always contains **the complete original source roster**, not only selected/visible items.
- `PRIVATE-HUMAN-sensitivity-template.csv`: immutable source-bound manual editor alternative. **Copy** this file before editing it; never overwrite the original.
- `PRIVATE-triage-bindings.json`: unsigned exact original completed manifest/decision-byte digests, slot roster and literal false authority fields. Keep this PRIVATE.

In the browser, choose per source one of `PENDING`, `REVIEW_REQUIRED`, `WITHHOLD`. Select `UNKNOWN` **alone**, or one or more categories in canonical order `CREDENTIALS|PERSONAL_DATA|CLIENT_DATA|OTHER`. No status is a clearance. Free text is at most 300 characters and cannot begin with spreadsheet formula characters even after whitespace. Avoid copying actual secrets or PII into follow-up notes.

### Unicode-disguised spreadsheet formula notes remain HOLD

The original private HUMAN decision CSV, HUMAN sensitivity follow-up CSV,
private discussion actions, HUMAN proposed-team notes and agenda questions
now share a **server-side fail-closed Unicode formula-prefix admission**.
Besides ordinary `=`, `+`, `-`, `@` and leading whitespace, it rejects
compatibility-equivalent prefixes (including fullwidth forms), leading
invisible/combining Unicode markers, unsafe controls and bidirectional
formatting that can disguise spreadsheet interpretation. The offline
original HUMAN and sensitivity editors also warn/refuse these forms before
saving a draft; the native command remains authoritative.

This applies only to original PRIVATE HUMAN note/question acceptance under
`private-assessment-notes/`, **not** the separate authenticated client
finding CSV exporter already owned by an independent PR. No original
PRIVATE human note bytes are silently normalized, modified or removed.
Older original review packets containing newly refused Unicode/format
prefixes intentionally remain HOLD on native reopening: a HUMAN source owner
must prepare a NEW original-source-bound acceptable note/CSV rather than
silently migrating historical evidence. Passing this check is NOT proof
that any output is safe to share or authenticated.

**Resume:** the browser editor can reopen one earlier **browser-generated complete** PRIVATE HUMAN CSV through the local **Resume exact-source previous PRIVATE HUMAN browser CSV** picker. The editor fatally decodes UTF-8, checks the exact full row count, complete source ordinal/byte-SHA roster and all original HUMAN statuses, categories and notes before **any** state change. It asks for an explicit HUMAN confirmation; cancellation or a single mismatch leaves all current editor choices untouched. This restores only draft UI inputs, not privacy clearance, local file permissions, provenance, consent, or any finalizer receipt. No file is uploaded. The original native source re-admission on finalize remains required.

After saving the browser-generated `PRIVATE-HUMAN-sensitivity-completed.csv`, move it to an owner-private location and `chmod 600` it: ordinary browser downloads may default to world-readable permissions.

```sh
chmod 600 /private/owner/PRIVATE-HUMAN-sensitivity-completed.csv
python3 private-assessment-notes/notes.py sensitivity-finalize \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --triage-kit /private/owner/PRIVATE-lightup-sensitivity-draft-ORIGINAL \
  --completed-csv /private/owner/PRIVATE-HUMAN-sensitivity-completed.csv \
  --private-parent /private/owner
```

The native finalizer reopens the complete **original completed packet** through the original `load_workroom` and `load_decisions` validators, recomputes exact original byte digests and human stage totals, then reopens the unchanged original triage template and source roster. It refuses any source drift, revised original decisions, malformed/extra/reordered/missing rows, unsafe human note, unknown category/status, forged authority flag, or non-private input. Successful local HUMAN review **still exits HOLD (3)**, not PASS. It writes a separate 0700/0600 `PRIVATE-lightup-sensitivity-review-*` containing private scriptless HTML, complete operator concerns CSV and an unsigned source-bound receipt with only counts and literal false authority flags. No note content, filenames, grants or client evidence are copied. A failed finalizer does not overwrite either input.

### Operator limitations and release gates
A status, SHA digest, masked note or category reflects HUMAN-local proposals; it is not verified absence/presence of a secret, safe anonymization, true source provenance or independently authenticated HUMAN identity. Do not circulate these PRIVATE files. No automatic deletion or cryptographic identity/signature is claimed.

All original exact-head hosted and permanently registered named VPS CI, source-owner acceptance, independent security/privacy/browser review, existing #177/#182/#829, separately authenticated current client and operator consent with action-time revocation and explicit HUMAN GO remain mandatory before any eventual main merge, deploy, disclosure or active assessment. This draft adds no QA/test suite and does not change the underlying scanner, authenticator, authorization policy, grant, or original producer.

## Minimum-necessary HUMAN concern follow-up (optional)

After a native `sensitivity-finalize` has created its complete original-bound PRIVATE review, an operator can choose **exactly one** topic and **exactly one** HUMAN review status for a separate internal meeting preparation. No actual team identity or audience is authenticated.

```sh
python3 private-assessment-notes/notes.py sensitivity-focus \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --triage-review /private/owner/PRIVATE-lightup-sensitivity-review-ORIGINAL \
  --topic PERSONAL_DATA \
  --status REVIEW_REQUIRED \
  --private-parent /private/owner
```

The new exclusive owner-only `PRIVATE-lightup-sensitivity-focus-*` contains a scriptless PRIVATE HTML agenda and selected-only CSV with original ordinal, local HUMAN status, concerned category and local HUMAN question; it contains **no original or masked note text, original filename, individual SHA digest or unselected row**. Its separate PRIVATE receipt binds the original full manifest, original completed HUMAN decisions and complete sensitivity receipt/CSV by unsigned SHA-256, with literal-false authorization/disclosure flags. Before emitting anything, the original native completed source roster and decisions are independently re-admitted, every original triage row/category and aggregate count is rechecked, and the selected subset is taken only from that exact complete review. Empty match or mismatch is HOLD without an agenda. A local choice of category/status is not proof of the identity, access level, consent or clearance of any potential recipient. No packet is sent automatically; outcome is always **HOLD (3)**.


## Longitudinal HUMAN sensitivity history and next local review

The same original completed masked-note packet can now be revisited across **2–8 genuine, separately finalized owner-private HUMAN sensitivity review directories**. Historical inputs are explicit, in HUMAN-declared order; there is no scan, filesystem discovery, implicit publication, timestamp authentication or inferred security improvement.

```sh
python3 private-assessment-notes/notes.py sensitivity-history \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-ROUND1 \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-ROUND2 \
  --private-parent /private/owner
```

The new 0700/0600 history workroom contains:
- `OPEN-PRIVATE.html`, a self-contained local navigation page.
- `PRIVATE-HUMAN-timeline.html`, an offline interactive, CSP hash-pinned browser timeline. Switch HUMAN rounds, filter per status or original ordinal, show only changed original positions and inspect the local categorical history for a source. **No original note bytes, source hashes, filenames or HUMAN free-text notes are included in this browser artifact.**
- `PRIVATE-HUMAN-history.html`, a scriptless, printable, source-number-only historical overview.
- `PRIVATE-HUMAN-transitions.csv`, the complete per-source/per-adjacent-round literal change table; it describes reported HUMAN changes only, not verified improvement. A free note change is represented by a Boolean, not its content.
- `PRIVATE-HUMAN-round-counts.csv`, owner-private count-only aggregate overview per round. Small cohorts can still be sensitive; do not treat these counts as anonymously publishable.
- `PRIVATE-HUMAN-history-bindings.json`, a private unsigned manifest of original exact manifest/HUMAN CSV bytes, all original round receipts, all full CSV digests and literal-false authority flags.
- `PRIVATE-HUMAN-last-round.csv`, an explicitly PRIVATE copy of the last full HUMAN decisions. **This file can contain HUMAN note text. Do not share it.**
- `PRIVATE-HUMAN-sensitivity-template.csv`, `PRIVATE-triage-bindings.json`, and a new independent blank `PRIVATE-HUMAN-sensitivity-editor.html` for the **next HUMAN review**. Every source starts at `PENDING`/`UNKNOWN` rather than silently keeping a prior purported clearance. To continue with prior choices, a human must select `PRIVATE-HUMAN-last-round.csv` in the local editor and explicitly confirm full source-bound restoration.

To finalize the next HUMAN round, download the editor's complete CSV into a new 0600 private file and call the **unchanged existing native** `sensitivity-finalize`. The history kit acts as `--triage-kit` because it contains the complete original-bound immutable template and source receipt; the unchanged original completed masked-note packet must still be supplied.

```sh
chmod 600 /private/owner/PRIVATE-HUMAN-sensitivity-next.csv
python3 private-assessment-notes/notes.py sensitivity-finalize \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --triage-kit /private/owner/PRIVATE-lightup-sensitivity-history-ACTUAL \
  --completed-csv /private/owner/PRIVATE-HUMAN-sensitivity-next.csv \
  --private-parent /private/owner
```

The history builder re-admits **every** original completed review against the original source SHA/byte identity, full original HUMAN CSV, category/status count receipts and literal-false authority flags. Separate original review directories with identical HUMAN decision CSVs are permitted, with exact-copy slot pairs recorded as **not proof of independently authenticated reviewers or progress**. Repeating the same directory path or changing a single original source still refuses the entire history. The next round is an independently finalized new PRIVATE HUMAN packet, not a revision of earlier results. All history artifacts stay local owner-private. A reduction in `WITHHOLD` or `REVIEW_REQUIRED` is only a local human reclassification, **never** evidence of sanitization, consent, remediation or security PASS.


## Source-bound HUMAN attention-only handoff from two reviews

The original complete 2–8-round history lets the operator understand drift without calling it remediation. A separate foreground native route can prepare a **minimum-necessary, local PRIVATE HUMAN attention agenda** from any **two distinct, independently finalized original source-bound sensitivity reviews**, even before producing a larger timeline:

~~~sh
python3 private-assessment-notes/notes.py sensitivity-attention \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --earlier-review /private/owner/PRIVATE-lightup-sensitivity-review-ROUND1 \
  --later-review /private/owner/PRIVATE-lightup-sensitivity-review-ROUND2 \
  --kind CHANGES_ONLY \
  --topic PERSONAL_DATA \
  --private-parent /private/owner
~~~

One of three explicit HUMAN-only local filters is mandatory. `ALL_ATTENTION` includes only new literal changes or the current human-labeled WITHHOLD/REVIEW_REQUIRED rows; `CHANGES_ONLY` includes changed local HUMAN stage/categories or free-note-change flags; `CURRENT_WITHHOLD` includes sources still locally marked WITHHOLD. An optional category narrows exclusively to one category **in the latest original review**, never to a guessed client scope. An empty selection refuses with HOLD.

The native source re-opens the original completed source/decision packet and **both** complete original sensitivity round receipts and full original CSVs. Each selected source position is bound to its ordinal, the unsigned original manifest, complete HUMAN decision digest and both exact completed review receipt/CSV digests. The new 0700/0600 owner-only packet contains a private, scriptless HTML conversation board, selected-only CSV and PRIVATE receipt. The board shows only original ordinal, two HUMAN stages, two declared categories, and Boolean HUMAN note present/changed. **No original or pattern-masked note contents, original source filename/digest, or free-text HUMAN note contents appear in the browser/CSV.** Nothing is sent.

Status/category transitions are HUMAN opinions, not verified privacy improvement. A drop from WITHHOLD to PENDING, disappearance of a listed category or unchanged free notes does **not** establish that any sensitive data was removed or that anything can be disclosed. The command **always exits HOLD (3) even after successfully writing a PRIVATE human conversation proposal**. All original current separately authenticated client/operator consent, action-time revocation, independent privacy/security/source-owner approvals and HUMAN GO requirements remain unchanged.


## Multi-reviewer PRIVATE HUMAN sensitivity reconciliation — complete offline Studio

Operators reviewing **2–8 separately completed PRIVATE HUMAN sensitivity packets** for the same original completed masked-note source can now reconcile *human-declared disagreements* in one locally opened workroom. This is a separate conversation and drafting product, **not** an automatic majority-vote decision or a grant.

~~~sh
python3 private-assessment-notes/notes.py sensitivity-reconcile \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-REVIEWER1 \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-REVIEWER2 \
  --private-parent /private/owner
~~~

The original completed notes packet and **every supplied completed sensitivity review** are re-admitted through the unchanged original native source checks. Each has the exact original source-byte manifest, complete original HUMAN decisions, reviewer CSV/receipt digests, and full source roster/stage/category counts independently matched. Identical reviewer directory paths refuse. Separately selected original packets that contain byte-identical HUMAN decisions are now admitted as **declared review slots**, with every exact-copy slot pair recorded in the PRIVATE unsigned receipt and shown in the offline Studio. These copies must NOT be interpreted as independent reviewers or corroborating evidence; these files still **cannot establish the actual identity, independence, qualifications or consent of any real reviewer**.

The resulting new 0700 directory and 0600 files contain:
- **`PRIVATE-HUMAN-reconciliation-studio.html`**: a standalone, offline, self-contained browser comparison with CSP SHA-pinned script and `connect-src 'none'`. Per original source position, shows each manually numbered reviewer slot's declared stage, category labels and whether an undisclosed HUMAN note exists. Filter category/status disagreements or ordinal. Blank next-round HUMAN draft always defaults to **PENDING/UNKNOWN**. An operator may manually set statuses, check categories and write a new short PRIVATE question. A previous reviewer's HUMAN stage/categories can be locally copied to **one source only**, following an explicit confirmation, never the original free-text note. All 1–12 original positions remain in the complete exported CSV irrespective of filtering.
- `PRIVATE-HUMAN-reconciliation.html`: printable scriptless detailed HUMAN reviewer matrix. It distinguishes label/category disagreements, changed PRIVATE note values (only Boolean indicators), and any claimed WITHHOLD. Agreement never implies privacy PASS.
- `PRIVATE-HUMAN-discussion.html`: only original source positions with mismatched local human proposals or pending attention, no original note content or actual reviewer identities.
- `PRIVATE-HUMAN-reconciliation.csv`: bounded all-original review-slot matrix of original ordinals, HUMAN statuses/categories, note-present flags and literal mismatch flags. This CSV never contains original/masked note text, free HUMAN notes, filenames or source hashes. It is PRIVATE nonetheless.
- `PRIVATE-HUMAN-reconciliation-bindings.json`: unsigned original source/HUMAN-decision-byte-bound original review manifest, with each actual reviewer packet's original unsigned receipt/CSV SHA and authority fields literally false. No validated reviewer identities.
- `PRIVATE-triage-bindings.json`, `PRIVATE-HUMAN-sensitivity-template.csv` and `PRIVATE-HUMAN-sensitivity-editor.html`: **new blank, original-bound** next HUMAN review source kit. No reviewer vote is silently made authoritative.

**PRIVATE HUMAN draft-resume within the combined reconciliation Studio:** a saved, browser-produced complete original-bound `PRIVATE-HUMAN-sensitivity-completed.csv` may be consciously re-opened locally. The Studio uses fatal UTF-8 decode, rejects noncanonical/extra/missing/reordered rows, checks every original ordinal and SHA, exact declared HUMAN stages/category-order and safe note text **for the entire original source roster** before changing any local input. It asks for an additional HUMAN confirmation. One mismatch/cancel leaves every existing choice untouched. It does not restore or import the original reviewers' confidential notes, claim a reviewer identity or bypass the unchanged native finalizer. Browser-saved CSV files may be world-readable until moved into a 0600 owner-only directory.

**Complete native handoff:** open `OPEN-PRIVATE.html`, read the Studio, manually choose the next original-bound HUMAN proposals, download `PRIVATE-HUMAN-sensitivity-completed.csv`, move the browser download into a secure private location and `chmod 600`. Then explicitly call the **already existing original** `sensitivity-finalize` with `--triage-kit` set to the new reconciliation workroom, `--completed-packet` pointing to the **same unchanged original**, and `--completed-csv` pointing to the private browser download. The original native strict CSV and source-byte checks continue to apply, with no changed authority or consent boundary. This finalizer still exits **HOLD (3)**, even when it writes a new complete HUMAN review.

The browser/editor does not upload, send, schedule, grant, scan, model, execute, inspect active targets, prove privacy safety or authorize any external recipient. Reviewers' free notes are examined internally for equality only to highlight disagreements, but the original text is not copied into exported reconciliation displays. The original review packets stay untouched. Existing exact-head hosted/permanent named VPS CI, source-owner and independent privacy/security/browser approvals, #177/#182/#829, current separately authenticated client/operator consent including at-action revocation and explicit HUMAN GO remain mandatory before any later main merge, release or customer action.


## One-command PRIVATE HUMAN review workbench — original rounds OR peer submissions

The native **`notes.py sensitivity-workbench`** route now creates ONE owner-private offline workroom with an explicit mode. It composes the existing original source-bound reviewers/readers, printable HTML summaries, source-limited counts/CSV and complete next independent HUMAN draft, instead of requiring separate manually gathered history/reconciliation artifacts. `timeline` means **manually ordered human versions**; `reviewers` means **manually supplied HUMAN submission slots**. Neither mode authenticates actual authors, chronology, risk clearance or customer consent.

For longitudinal human revision history:

~~~sh
python3 private-assessment-notes/notes.py sensitivity-workbench \
  --mode timeline \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-EARLIER \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-LATER \
  --private-parent /private/owner
~~~

For multiple independent *declared* HUMAN submissions:

~~~sh
python3 private-assessment-notes/notes.py sensitivity-workbench \
  --mode reviewers \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-REVIEWER1 \
  --review /private/owner/PRIVATE-lightup-sensitivity-review-REVIEWER2 \
  --private-parent /private/owner
~~~

Both modes require **2–8 distinct ordinary owner-private review directories**, each re-admitted by the original full private source/HUMAN-decision/round/receipt validators before creating anything. Byte-identical HUMAN CSV content in separate originals remains eligible but every pair is shown in the receipt as unverified same-content HUMAN submissions, never evidence of independent identity or privacy improvement. A duplicate directory path or source drift causes HOLD.

One new 0700/0600 `PRIVATE-lightup-sensitivity-workbench-*` contains the scriptless `OPEN-PRIVATE.html` and a set of links:
- `PRIVATE-HUMAN-board.html`: existing offline, CSP-pinned interactive *timeline* or *reviewer comparison/next draft Studio* depending on explicit mode.
- `PRIVATE-HUMAN-overview.html`: existing scriptless, printable HUMAN overview. A reduction in local concern counts is not verified remediation.
- `PRIVATE-HUMAN-detail.csv`: either full original-position adjacent-round transition records or bounded reviewer-slot categorical matrix (no prior HUMAN free text).
- `PRIVATE-HUMAN-compact.csv`: PRIVATE counts per human round or minimum-necessary original-position dispute signals. Neither automatically qualifies as safe-to-publish anonymous data.
- `PRIVATE-HUMAN-workbench-bindings.json`: all original source/HUMAN-byte receipts, each actual completed original review receipt/CSV digest, declared slots, same-content pairs and literally false authority fields.
- Blank **`PRIVATE-HUMAN-sensitivity-template.csv`**, **`PRIVATE-HUMAN-sensitivity-editor.html`**, and **`PRIVATE-triage-bindings.json`**: full canonical source-bound next HUMAN review at PENDING/UNKNOWN. In *timeline* mode the separate `PRIVATE-HUMAN-last-round.csv` contains the exact most recent complete original HUMAN note choices, including PRIVATE note text. Keep it PRIVATE.
- No scans, model calls, network, auto consensus, client data upload, external recipients, grants, retention deletion or release actions are triggered.

**Next native step**: open the local workbench index, review the source and HUMAN declarations, consciously export the full source-bound next HUMAN decision CSV, move the downloaded CSV to an owner-only 0600 location, and run the **unchanged** `notes.py sensitivity-finalize --completed-packet ORIGINAL --triage-kit THE_NEW_WORKBENCH --completed-csv OWNER_PRIVATE_FILE --private-parent OWNER_PRIVATE_0700`. All original source admissions, actual consent and downstream independent release reviews remain unchanged. Even an accepted new local review continues to return **HOLD (3)**.

### Persisted CSV byte-binding correction

The native `sensitivity-finalize` now binds its unsigned HUMAN CSV receipt to the **exact canonical UTF-8 CSV bytes actually written in the owner-private final packet**, rather than the differently quoted browser/manual input. This ensures the existing native `history`, `reconcile`, `attention` and `workbench` admission can verify exact stored bytes consistently. The source owner's identity is not authenticated by this digest. **Older completed packages with a mismatched stored CSV/receipt digest remain HOLD**: never rewrite them in place or relabel a failed receipt as valid. A HUMAN operator must repeat the existing original native finalization using the unchanged original completed source, unchanged original triage kit and the original complete source-bound HUMAN decisions CSV to create a distinct fresh PRIVATE packet. There is no automatic migration, forged proof or relaxed hash check.


### Integrated PRIVATE reviewer discrepancy navigation and selected-source handoff

The original-bound [offline multi-reviewer Studio](privacy_triage_reconcile_studio.py) now makes all three kinds of HUMAN disagreement visible **without exposing private note text**: declared stage, declared privacy category, and whether the content of free HUMAN follow-up notes differs. The original free HUMAN notes remain exclusively in their PRIVATE completed packets; the browser receives one `noteDisagreement` Boolean per original, never note contents or guessable hashes of note strings. The local dropdown deliberately filters **all**, **any disagreement (including note-only)**, **note differences only**, **any declared WITHHOLD**, **any declared REVIEW_REQUIRED**, or **identical local human status/category/note choices**. It also reports source counts and warns about exact duplicate-content reviewer slot pairs. Filtering changes only the visual view: a complete next HUMAN CSV still includes **all original source positions**, so hidden positions cannot silently disappear from the native strict original source roster.

The unified `sensitivity-workbench` now includes `PRIVATE-HUMAN-attention.html` in **both** `--mode timeline` and `--mode reviewers`: a separate scriptless, printable, **selected-original-only** private conversation agenda. Timeline mode includes only original positions with a HUMAN stage/category/note-content change in declared rounds, or still locally labelled WITHHOLD/REVIEW_REQUIRED in the last round. Reviewer mode reuses the existing original source-bound multi-reviewer discussion agenda. No source text, source SHA, filenames or private HUMAN note contents are copied into this source-minimized print view. It is never a customer-ready, publishable report.

In reviewer mode, the additional `PRIVATE-HUMAN-compact.csv` now also lists **only** original positions with declared HUMAN attention, instead of unnecessarily disclosing unchanged/uninteresting positions. The CSV includes literal separate flags for status disagreements, category disagreements, hidden free HUMAN note differences, and any declared WITHHOLD/REVIEW_REQUIRED. The separate full source-bound reviewer matrix remains available in the owner-private `PRIVATE-HUMAN-detail.csv`, and the unchanged **complete canonical next HUMAN CSV** remains mandatory for any native finalization. A compact/private handoff never grants access to source content, nor does it signify verified remediation, privacy clearance, recipient authentication, consent, signed evidence or a security PASS.

No QA/regression/test suites, scanner targets, external requests, automatic sends, permission grants or existing release-gate changes are introduced.


### Two separate offline Studio CSV exports — complete review vs. selected discussion

The original-bound reviewer Studio now has **two deliberately different local download actions**. The primary **Save COMPLETE PRIVATE original-bound HUMAN decisions CSV** always exports **every original source position** with its original unsigned SHA, the operator's independently chosen HUMAN stage, canonical selected categories and new private HUMAN free note text. It is the **only** browser-generated CSV appropriate for the separate original native `sensitivity-finalize`, after moving it to an owner-only 0600 location.

The new **Save PRIVATE selected HUMAN discussion rows** button exports **only the source positions visible under the operator's current ordinal and attention filters**, with selected columns: original ordinal, stage disagreement, category disagreement, note-content disagreement (Boolean only), any declared WITHHOLD, any declared REVIEW_REQUIRED. It excludes original source SHA, filenames, source text, redacted source text, any previous/new free HUMAN note text, reviewer IDs and any authority/recipient token. It is for local, owner-private conversation **only**, never a source-bound final review or authorized external evidence handoff. An empty visible selection produces no download. The downloaded CSV still needs deliberate safe local handling: a browser download is not automatically a 0600 private file. Visual filtering, printing or selected-discussion downloads **never drop source rows** from the distinct full next-human-decision CSV or change existing source admission/release gates.


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
