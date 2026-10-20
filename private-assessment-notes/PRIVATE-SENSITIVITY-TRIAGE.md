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

This creates a **new** `PRIVATE-lightup-sensitivity-draft-*` owner-only directory, with:

- `OPEN-PRIVATE.html`: readable human-only original-slot concern preview, not a source-text viewer.
- `PRIVATE-HUMAN-sensitivity-editor.html`: fully offline, accessible browser editor with CSP hash-pinned script and `connect-src 'none'`; no local/session storage or remote libraries. The operator can choose HUMAN concern statuses per ordinal, identify potential sensitive categories, and enter a short private follow-up question. Download always contains **the complete original source roster**, not only selected/visible items.
- `PRIVATE-HUMAN-sensitivity-template.csv`: immutable source-bound manual editor alternative. **Copy** this file before editing it; never overwrite the original.
- `PRIVATE-triage-bindings.json`: unsigned exact original completed manifest/decision-byte digests, slot roster and literal false authority fields. Keep this PRIVATE.

In the browser, choose per source one of `PENDING`, `REVIEW_REQUIRED`, `WITHHOLD`. Select `UNKNOWN` **alone**, or one or more categories in canonical order `CREDENTIALS|PERSONAL_DATA|CLIENT_DATA|OTHER`. No status is a clearance. Free text is at most 300 characters and cannot begin with spreadsheet formula characters even after whitespace. Avoid copying actual secrets or PII into follow-up notes.

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

The history builder re-admits **every** original completed review against the original source SHA/byte identity, full original HUMAN CSV, category/status count receipts and literal-false authority flags. Reused byte-identical round CSVs refuse as false new rounds, and a single altered/different source refuses the entire history. The next round is an independently finalized new PRIVATE HUMAN packet, not a revision of earlier results. All history artifacts stay local owner-private. A reduction in `WITHHOLD` or `REVIEW_REQUIRED` is only a local human reclassification, **never** evidence of sanitization, consent, remediation or security PASS.


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

The original completed notes packet and **every supplied completed sensitivity review** are re-admitted through the unchanged original native source checks. Each has the exact original source-byte manifest, complete original HUMAN decisions, reviewer CSV/receipt digests, and full source roster/stage/category counts independently matched. Identical reviewer paths or identical decision CSV bytes refuse; these files still **cannot establish the actual identity, independence, qualifications or consent of any real reviewer**.

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
