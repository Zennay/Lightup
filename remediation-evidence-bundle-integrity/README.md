# LightUp — PRIVATE Evidence Bundle Integrity & Handoff Desk

**INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This is a new, independently owned, read-only companion for the existing [Evidence Relationship Desk draft #1660](https://github.com/Zennay/Lightup/pull/1660), stacked on that exact existing draft without changing its source-owner files or any other parallel PR.

## What is usable now

The original one-command `remediation-evidence-reuse/desk.py workspace` produces one owner-private snapshot directory with original `current.json`, optional `previous.json`, the complete HUMAN `session.json`, the private static browser pages, `questions.json`, `counts.json`, and a SHA-256 `manifest.json`. A copied or edited folder may no longer correspond to the original snapshot. **This tool admits the complete folder atomically for a LOCAL read-only human check** before it is handed to the original operator. No single-file cherry-picking or partial success.

The verifier requires a real owner-private `0700` directory and `0600` regular single-link files; it refuses symlinks, extra/missing objects, unlisted contents, duplicate JSON property keys, unexpected manifest claims, ambiguous original schema, forged authority booleans, oversized artifacts, incomplete/renumbered HUMAN action rows, changed original source digests, and altered JSON/counts. It verifies every manifest-declared filename, exact bytes and SHA-256, checks the original ledger v1/unified HUMAN v2 packet with existing source-owner-pinned parsers, reruns the exact HUMAN proposal/session admission and independently recalculates the private `questions.json` and anonymous `counts.json`. It also **reconstructs all four original HTML pages** byte-for-byte with the pinned original renderers (not merely matching an editable checksum manifest): locally altered scripts, remote links, fake dashboard text and modified HUMAN views fail closed even when an attacker updates the unsigned manifest checksums. The original manifest itself must match canonical serialization. Finally it rereads files before publishing to reduce stale local reports. No network/active target/subprocess or database path exists.

The readable output is a **new standalone CSP-locked, no-script, owner-private HTML brief** containing only aggregate local counts and local HUMAN stage totals — not file names, paths, source/client IDs, SHA digests, plaintext evidence, free-text HUMAN notes or per-finding identities. The verifier also prints a minimal counts-only local console summary. Original files are never rewritten.

## Operator workflow

On a trusted local Linux machine with the original branch code installed, produce the original PRIVATE directory using its existing instructions:

```sh
install -d -m 700 "$HOME/lightup-private"
python3 remediation-evidence-reuse/desk.py workspace \
  --current "$HOME/lightup-private/ledger-current.json" \
  --output-dir "$HOME/lightup-private/desk-001"
```

Make a **separate, existing owner-only 0700 directory** for the newly published report. Then inspect the original directory *without modifying it*:

```sh
install -d -m 700 "$HOME/lightup-private/receipts"
python3 remediation-evidence-bundle-integrity/verify.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --report "$HOME/lightup-private/receipts/desk-001-integrity.html"
```

For a separate source-free local aggregate JSON instead of HTML:

```sh
python3 remediation-evidence-bundle-integrity/verify.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --counts "$HOME/lightup-private/receipts/desk-001-anonymous.json"
```

This second output includes only anonymous stage and open question-reason counts; no source IDs, file digests, paths, notes, or finding identities. The HTML now includes a plain-language HUMAN follow-up table by original proposed-question reason. One question may count under more than one reason. Both output options are intentionally mutually exclusive to avoid partial multi-output publication.

**Exit 2** is intentional `REVIEW_ONLY`: local byte/source/HUMAN consistency admitted, never an approval or security verdict. **Exit 3** means `HOLD`, and no report is produced. `--report` is optional for a console-only inspection. A report name must be unused. The verifier cannot write inside the original bundle; the original directory may remain immutable. Open the HTML locally only, not on a web server.

Private exports must never enter public GitHub PRs, Notion pages, third-party tools or CI artifacts. If any byte fails, re-export from the original trusted source; do not patch `manifest.json` to force a local match. A manifest is **not signed**, a locally modified manifest and contents can agree, and private SHA hashes cannot authenticate who produced the original packet or prove the evidence file bytes exist. Source reference, original owner, client or engagement labels and HUMAN notes are self-declared; this is solely a local *internal-consistency* assistant.

## Original-source PRIVATE HUMAN progression across complete workspaces

`progression.py` compares **2–12 already completed, independently admitted owner-private workspace directories**, with strict same-actual-original-PACKET-BYTES (both current and previous when present), exact original HUMAN proposal membership, no duplicated session bytes, and no claimed authenticated chronology. It never modifies the earlier workspace or interprets a disappearing evidence link as fixed.

```sh
python3 remediation-evidence-bundle-integrity/progression.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --bundle "$HOME/lightup-private/desk-002" \
  --html "$HOME/lightup-private/receipts/private-historical-review.html"
```

Instead of `--html`, choose **only** `--counts /ABSOLUTE/NEW/ANONYMOUS.json` for an aggregate-only JSON. Both outputs contain ordered **slot numbers**, local stages, reopened HUMAN questions, locally answered questions, changed stages, and a count of notes that changed (never free text, original IDs, source hashes, individual fingerprint labels, or paths). The operation deliberately refuses duplicate identical HUMAN sessions; slot order is user-supplied **not authenticated time order**. Verify all source and HUMAN bytes again before publication. Unmatched original source/client, changed HUMAN proposed-question identity, or any invalid bundle results in complete HOLD and no output.

This is useful to hand over an offline readable status progression while keeping original report files and PRIVATE HUMAN notes on their own owner-controlled machine. Even an increase in locally answered questions says nothing about verified remediation, retesting, consent or actual authorization.

## Separate-source PRIVATE HUMAN portfolio board

`portfolio.py` now accepts 1–12 separately admitted, complete PRIVATE Evidence Relationship workspaces from **one or more original sources or contexts**. Each original workspace independently passes the exact same file/manifest/HUMAN session review as `verify.py`. It never merges source records, invents shared client identities, extracts evidence-byte contents or touches native LightUp requests. The operator gets a source-ID-free, scriptless private workload board with per-slot local HUMAN question counts, pending stages, outstanding follow-up reason groupings, and aggregate **slot workload** totals. It detects identical repeated source+HUMAN snapshots (HOLD) and highlights repeated original source packet identities across different human sessions to warn against double-counting. This is not an organization-wide set of authenticated distinct cases.

```sh
python3 remediation-evidence-bundle-integrity/portfolio.py \
  --bundle "$HOME/lightup-private/desk-client-A" \
  --bundle "$HOME/lightup-private/desk-client-B" \
  --html "$HOME/lightup-private/receipts/private-workload.html"
```

Or choose **only** `--counts /ABSOLUTE/NEW/SOURCE-FREE.json` for an aggregate local JSON intended for **private** staffing discussions, not public telemetry. Both options require an unused name in an existing owner-only directory. Source filenames, digests, client references, original finding identifiers and private free-text notes are **never exported** into this portfolio. Private per-slot workload counts may still reveal business-sensitive staffing information, so no online publication or public issue attachment is appropriate. Totals sum *local slots*, not unique customers, proven evidence or complete findings. Repeated packet groups are flagged by slot numbers only; no original identity leaves memory.

## One-command source-owner workroom: original evidence + portable HUMAN cockpit

**New `prepare.py`:** instead of manually exporting every original Evidence Relationship Desk workspace and then running a second composition command, a source owner can take existing PRIVATE original packet files straight through the native original HUMAN proposal/renderers into **one atomically published complete offline workroom**. The workroom includes privately preserved original source-bound desks *and* a separately distributable source-free Cockpit, all using the same existing original interfaces. No external network, subprocess, test suite, scanner, grant, file evidence byte inspection or native Apply path is involved.

The source owner first places already-exported original local input files in separate **existing 0700 folders**, each with `current.json` and optionally `previous.json` / `session.json`, all 0600 regular owner-only files. No other files are allowed in these input directories, and no original evidence bytes or clients may be exported from an unapproved source. Each source must already satisfy the original pinned Evidence Ledger/HUMAN contract. Existing stored HUMAN sessions are admitted, not replaced; without a session, an original human-only `open` review journal is prepared. The original inputs stay unchanged.

```sh
install -d -m 700 "$HOME/lightup-private/ledger-01"
# Place existing original current.json, optional previous.json/session.json as 0600 files.
python3 remediation-evidence-bundle-integrity/prepare.py \
  --input-dir "$HOME/lightup-private/ledger-01" \
  --output-dir "$HOME/lightup-private/workroom-001"
```

**Reuse already completed original Evidence Relationship Desks:** the same atomic workroom command now also accepts `--bundle /ABSOLUTE/ORIGINAL-DESK` for a **fully existing**, original source-owner PRIVATE Evidence Relationship Desk (with original complete source/workspace manifest, immutable originals and HUMAN session already present). This is admitted in full by the existing `verify.py` and then copied *byte-for-byte* through the original atomic workspace publisher; it never discards completed HUMAN notes and needs no manual re-export to an artificial raw input folder. Use `--bundle` alone or mix with repeated `--input-dir` for up to 12 original workspaces. Raw `--input-dir` folders occupy initial slot numbers; full `--bundle` folders follow in CLI order. Both original inputs must be completely owner-private and remain unchanged. Duplicate identical source+session snapshots HOLD to avoid false double-counted workload.

```sh
python3 remediation-evidence-bundle-integrity/prepare.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --output-dir "$HOME/lightup-private/workroom-from-original-001"
```

For 2–12 sources, repeat `--input-dir`; never duplicate the same source folder. An existing owner-only 0700 parent is mandatory and `--output-dir` must be completely new, outside every input folder. The native original source renderer prepares `original-01/`, etc., preserves original HUMAN source-bound notes and original PRIVATE pages, and then the existing `board.py` creates `cockpit/`. The new root `index.html` is a **ready-to-open local operator navigation desk** linking the original private source-bound reviews and combined anonymous human action/workload brief. It also links to **`tasks.html`**, a substantial new original-source-only human work queue produced by `workroom_actions.py`: every original admitted proposed question is grouped into *needs source owner*, *open*, *currently in human review* and *locally answered*, with record-level original claimed finding ID and local SHA label, its exact native reason-specific human prompt, and a link back to the owning original source inbox. Stages are ordered for manual routing, **never** inferred security severity. Free-text HUMAN notes are not duplicated; only a `PRIVATE note present` flag appears. The task queue stays **outside** the source-free `cockpit/`, is scriptless and owner-private 0600, and is never part of receiver transfer.

With an already-created single original workroom, it can also be published independently to a fresh unused file in that workroom root:

```sh
python3 remediation-evidence-bundle-integrity/workroom_actions.py \
  --bundle "$HOME/lightup-private/workroom-001/original-01" \
  --html "$HOME/lightup-private/workroom-001/new-private-actions.html"
```

When supplying 2–12 originals they must be named `original-01` through `original-12` in the exact same local workroom parent. This local output is PRIVATE, NOT anonymous; never send it to a receiving operator or publish to CI/GitHub. It only helps the original source owner find the precise HUMAN rows needing discussion and does not modify stage, consent, original finding, scan state or review permissions.
 The exact workroom directory becomes visible together only via the original exclusive atomic directory rename; before publication, every input source and HUMAN session is re-read for drift. On admission failure no completed destination is published.

**Recipient handoff (recommended one-command safe export):** the new `handoff.py` first re-admits the *whole* completed source-free `workroom-001/cockpit/` with `read_cockpit.py`'s native receiver logic. It then exclusively copies ONLY the whitelisted canonical anonymous portfolio/HTML/optional history files into one **new** owner-private, atomically published 0700 recipient folder containing 0600 files, after re-reading the same original cockpit bytes and manifest. It refuses unknown extra names, changed pages, unsafe roots and output locations within the original workroom. There is **no ZIP, archive, upload, transfer, email, browser JS, encryption claim or network**; this is a local preparatory folder under an existing private parent.

```sh
python3 remediation-evidence-bundle-integrity/handoff.py \
  --workroom "$HOME/lightup-private/workroom-001" \
  --output-dir "$HOME/lightup-private/receipts/for-human-recipient-001"
```

The source owner must arrange any separately authorized, authenticated and confidential means of moving **only this new source-free folder** to the intended receiver. On the trusted receiving machine, run `read_cockpit.py --cockpit /ABSOLUTE/PRIVATE/RECEIVED-FOLDER` first, then open the static `index.html` locally. This exporter neither signs the source nor encrypts network transport, cannot authenticate the sender, and does not imply that business workload counts are public. For a manual fallback, copy **ONLY** `workroom-001/cockpit/` and run the same native receiver command there. Never transmit `workroom-001/` itself or any `original-XX/` subfolder: those contain original client/source labels, unverified SHA references and private HUMAN notes. The source-free cockpit remains a local human-only workload snapshot, not signed proof, clearance, client/operator consent, evidence authenticity or verified remediation. A crash may leave an owner-private temporary staging directory; do not assume files are safe to share outside the original private location.

## One-command complete PRIVATE HTML evidence cockpit

**Recommended one-or-more-workspace operator entrypoint:** `board.py` fully integrates the independent original-bundle verifier, cross-source HUMAN workload portfolio, optional same-source revision progress and an advisory follow-up briefing into one **complete new private browser-readable offline folder**. No hand assembly of individual HTML is needed; a source-unchanged bundle is reviewed with the original rendered HTML reconstructed byte-for-byte first.

```sh
python3 remediation-evidence-bundle-integrity/board.py \
  --bundle "$HOME/lightup-private/desk-client-A" \
  --bundle "$HOME/lightup-private/desk-client-B" \
  --output-dir "$HOME/lightup-private/receipts/cockpit-001"
```

Open `cockpit-001/index.html` locally. The new private 0700 folder is created **atomically and exclusively** using the original parent workbench's Linux `renameat2(RENAME_NOREPLACE)` directory publisher, with fsynced 0600 files, scriptless Content Security Policy, source-free anonymous `portfolio.json`, `portfolio.html`, `actions.html` and its own unsigned output `manifest.json`. If two or more original input packets have identical source bytes and distinct HUMAN sessions, it also publishes `history.html` and `history.json` with only ordinal-local progression; otherwise it provides the multi-source workload and HUMAN action summary without pretending cross-client history exists.

The `actions.html` summary translates the original source-proposed reason codes into local HUMAN-only next steps and keeps each original owner slot separated. The cockpit **never** copies original source JSON, evidence bytes, filenames, source hashes, HUMAN notes or client IDs into its generated files. Nonetheless aggregate operational workload remains private. A changed original byte during preparation causes HOLD without publishing a final directory; an interrupted crash may leave an owner-private staging directory. `--output-dir` must be unused and its parent must already be owner-only 0700. This is a local advisory product: no task dispatch, native Apply, client grant, operator consent, verified fix or active assessment.

## Independent source-free offline cockpit receipt (no original customer files needed)

On a second **trusted, already authorized private machine**, a reviewer can check an exported **already-generated anonymized HUMAN-only cockpit** without transferring the underlying original source documents, original HUMAN note bodies or evidence bytes. The new `read_cockpit.py` requires a fully copied complete private cockpit folder, enforces literal 0700 + private 0600 files, exact canonical file manifest and whole-file hashes, and then **recomputes all standalone HTML views byte-for-byte from the aggregate-only `portfolio.json` and optional `history.json`** using the trusted product renderers. A changed page plus edited unsigned manifest is not accepted if it differs from the source-free JSON / deterministic browser renderer. HUMAN stage and pending-reason rows render in a **fixed original-schema order**, not whichever JSON object insertion order was used during file creation or receipt; a new canonical JSON parse cannot silently rearrange the operator's HTML or produce an inconsistent native receipt. Unknown or forged authority fields, invalid counts, impossible HUMAN stage distributions, reordered/unmatched slot histories, duplicate JSON property keys and unexplained source files cause complete HOLD. Original source, portfolio, history and cockpit manifest **warning/disclaimer strings must exactly match the native owner-pinned wording**; external input cannot hide unknown client data in an arbitrary 'warning' field. The source-free JSON and manifests must also be exact canonical original serialization rather than merely parse to the same dictionary.

```sh
python3 remediation-evidence-bundle-integrity/read_cockpit.py \
  --cockpit "$HOME/lightup-private/receipts/cockpit-001"
```

Exit 2 means the current local **self-declared** bundle is internally consistent. Exit 3 means it must be returned to the original private owner and never opened as a trusted workdesk. The receipt only prints source-free aggregate counts, writes nothing and does not reach any network/target/authorization subsystem. This feature is **not** an attestation of who sent it: anyone controlling both the aggregate JSON and unsigned manifest could fabricate a different internally consistent HUMAN-only cockpit. Original source authenticity, original custody, distinct consent, signed chronology, trusted producer authentication, security findings and verified remediation remain outside this tool and require their existing separate LightUp release safeguards. Do not confuse local byte reconstruction with cryptographic sender identification.

## Original-source HUMAN revisions: new complete offline workroom

The new `revise.py` closes the loop between the PRIVATE `tasks.html` source-owner action queue and the portable anonymous HUMAN cockpit. Original source records and earlier workrooms are immutable. Up to **64 source-bound HUMAN stage/note edits** across **1–12** original owner-private sources can be applied in one operation, with no execution, scan, grant, signed review or verified fix. Changes regenerate original native inbox/attention/manifest files and the source-free portable cockpit in a **NEW exclusively published private workroom**; source-owner PRIVATE notes never go into `cockpit/`.

First create a source-session-SHA-pinned **owner-only 0600 JSON plan**:
```sh
python3 remediation-evidence-bundle-integrity/revise.py \
  --workroom "$HOME/lightup-private/workroom-001" \
  --draft-plan "$HOME/lightup-private/receipts/human-revision-001.json"
```

Open the private JSON locally. Keep its generated `kind`, `schema_version`, `disposition`, `source_sessions` and `warning` unchanged. Change only `changes: []`: insert records indexed by **source slot and HUMAN row ordinal** from the PRIVATE `tasks.html` file, for example:
```json
{"slot":1,"ordinal":2,"stage":"needs_source_owner",
 "note_action":"replace","human_note":"Ask source owner to clarify local evidence."}
```

Stages are strictly `open`, `in_human_review`, `needs_source_owner`, `answered_human`. Note action is `keep` (empty `human_note`), `replace` (up to 1200 characters) or `clear` (empty `human_note`). No-op or duplicate edits and plans based on changed original HUMAN session bytes HOLD completely. Original timestamp is replaced only in the newly constructed session and is NOT authenticated chronology. Never enter private notes into command-line options.

Then atomically publish a new private source-owner workroom:
```sh
python3 remediation-evidence-bundle-integrity/revise.py \
  --workroom "$HOME/lightup-private/workroom-001" \
  --plan "$HOME/lightup-private/receipts/human-revision-001.json" \
  --output-dir "$HOME/lightup-private/workroom-002"
```

Every original input workroom source, local HUMAN journal, native task view, standalone cockpit, private edit plan and resulting source files must be consistent with unchanged native original parsers. Re-read immediately before exclusive atomic publication; if changed or incomplete the new destination is not published. Original source-owner files are never overwritten. Review stages remain HUMAN bookkeeping only, not verified remediation, source authenticity or approval. Use `handoff.py` separately to prepare ONLY the recipient's source-free standalone `cockpit/`.

## Fast single-question PRIVATE HUMAN amendment

For one source-owner question, use **`amend.py`** rather than manually editing a JSON batch plan. Select the existing slot and ordinal from `tasks.html`, choose an original HUMAN stage, and publish a completely **NEW** original workroom in one command:

```sh
python3 remediation-evidence-bundle-integrity/amend.py \
  --workroom "$HOME/lightup-private/workroom-001" \
  --slot 1 --ordinal 2 --stage needs_source_owner \
  --output-dir "$HOME/lightup-private/workroom-002"
```

To add a new PRIVATE source-owner note, place plain UTF-8 note text inside a trusted existing 0600 owner-private file under a 0700 private folder and add `--note-file /ABSOLUTE/PRIVATE/note.txt`. **Never** put HUMAN notes in a shell argument; to clear one in the new version use `--clear-note`. `--stage` may be omitted if only the note changes. The native original source-bound HUMAN journal is admitted before and after the edit. A temporary fresh 0700/0600 plan is internally constructed, and the existing full `revise.py` workroom-publishing path is reused; temporary note/plan material is removed after publication or HOLD. Only original stage and HUMAN note are affected, never the evidence, permission or security decision. For bulk edits across questions, keep using the strict 64-action `revise.py` private plan.

## Original PRIVATE workroom history: before → after HUMAN changes

New `compare_workrooms.py` compares **two FULL native source-owner workrooms** after a `revise.py` / `amend.py` revision (or two separately created complete workrooms). The source-slot count and **every exact original current/previous source packet** must match; otherwise HOLD. Each original HUMAN record is re-admitted with the pinned original native contract, and only actual local stage/note differences are listed. The operator supplies the before/after order; this is **not authenticated chronology**, not an identity claim or a security retest.

```sh
python3 remediation-evidence-bundle-integrity/compare_workrooms.py \
  --before "$HOME/lightup-private/workroom-001" \
  --after "$HOME/lightup-private/workroom-002" \
  --output-dir "$HOME/lightup-private/receipts/private-human-diff-001"
```

A **new private atomic directory** contains `index.html` with a readable HUMAN change summary, `details.html` with exact ORIGINAL PRIVATE source slot/ordinal, claimed finding ID, local SHA label and old/new HUMAN stages, and `counts.json` with anonymous counts only. Only a boolean notes-changed signal is shown: the original private free-text HUMAN note is **never exported or repeated** in the comparison page. `details.html` and the entire report directory remain source-owner-only and must **not** be copied into the portable recipient cockpit. Local `answered_human` is still not a verified remediation; reopening is not a confirmed security regression. Before publication both complete original workrooms are re-admitted again, original native browser pages rechecked, and the whole report is exclusively published 0700 with 0600 files; no earlier source is altered.

## Scope and release

No modifications to `src/`, original Evidence Artifact Ledger, Request Desk, native Apply, auth, scanner, scope, evidence files, CI or QA suites. Never feeds data to targets, issues grants, stages client action, changes HUMAN journals, concludes remediation or bypasses action-time revocation. As with the parent draft, **no main merge, production deploy or live use** until existing original exact-head hosted + permanently registered named VPS CI, original source-owner and independent security/privacy/browser/crypto reviews, #177/#182/#829, true independent revocable current client/operator consent and explicit HUMAN GO have all been satisfied. No new release gate is created by this utility.
