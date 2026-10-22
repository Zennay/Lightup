# LightUp · Isolated-lab batch launchpad

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** New-only `assessment-launchpad/` product pinned to original held CLI source commit `74e865201c8a4270e404046ef3447eb7f190edfb`. The original source owner, CLI, `_admit_explicit_lab_url`, `LabScenario`, and `ScopePolicy` files are not modified.

## Source-bound HUMAN return for PRIVATE manifest changes

After preparing the original PRIVATE saved before/after manifests and a `manifest_change_desk.py` report, use the bundled offline `manifest_change_review.html` to annotate the ordinal-only delta CSV. The native **`manifest_change_response.py`** receives that exact browser-exported `lightup-private-manifest-human-follow-up.csv` from a separate owner-private directory, reconstructs the original policy-admitted change report, binds the review rows to original change order and accepts only non-authorizing HUMAN stages. It generates three private artifacts: the canonical source-bound JSON, a scriptless CSP-pinned printable HUMAN return and privacy-minimal stage counts. Strict `--verify-output-dir` reopens the exact result read-only against all original source and answer bytes. No endpoint, source path or filename is embedded in the generated HTML/CSV; all stages are unsigned planning notes and cannot approve assessment, grant, consent, dispatch or release.

For consecutive independently saved HUMAN review exports, `manifest_change_rounds.py` re-admits **both** original source-bound native HUMAN returns against the same exact manifest-delta original, compares 1–32 ordinal rows and publishes an owner-private changed-stage CSV, source-bound JSON and scriptless CSP-pinned HTML. All source directories and results remain mutually separate; `--verify-output-dir` reopens the exact original bytes without rewriting anything. This is an unsigned HUMAN workflow change, **not** authenticated chronology, finding evidence, remediation status or permission.\n\n**[Full native CLI and browser-to-native workflow →](MANIFEST_CHANGE_RETURN_GUIDE.md)**. This command is a non-executing companion only. Source ownership, hosted/named-runner CI, independent reviews, the original separately authenticated client/operator consent and action-time revocation gates, and HUMAN GO remain mandatory. **INCUBATE M3/M7 · DRAFT/HOLD · not merged, not live.**

## Browser composer

Open `composer.html` locally. It is one standalone file with a strict hash-pinned CSP (no unsafe-inline script/style) and no external assets, APIs, storage, DNS or network access. Compose 1–16 distinct literal HTTP(S) URLs within the native CLI\'s 16 KiB manifest limit, or import a private existing local manifest using the explicit **replace** or **append after filled draft slots** mode. For file-append, the original file and the entire combined candidate are each admitted against the same 1–16 slot, strict UTF-8, native-byte-limit, duplicate and HTTP(S) convenience checks; append refuses invalid current rows and never silently truncates an overflow batch. A changed file-import mode or editor invalidates any earlier proposal; changes while the file is being read cancel import. Empty draft slots discarded during append require operator acknowledgement. A valid import is staged in a slot-by-slot current/proposed preview. Slot labels distinguish reorder-only slots, moved-out plus added values, removed plus moved-in values, true replacements and empty draft slots. The summary counts added/removed endpoint values independently from changed slot positions, so mixed reorder/add/remove edits are not misreported as only reorder operations. If the current draft contains duplicate endpoint rows, the preview warns that movement labels are ambiguous until those duplicates are removed. The editor remains untouched until explicit **Apply imported manifest**; operators can also **Download proposed manifest without applying** for separate local review, and **Cancel import** preserves the current editor. The preview discloses source byte/line counts plus blank/comment lines omitted and endpoint lines trimmed when producing canonical output. If normalization would discard or trim any lines, an explicit acknowledgement is required before Apply or canonical download. After Apply, **Undo last applied import** restores the previous editor only until the first subsequent editor change; the undo is invalidated on that first change and cannot later overwrite user edits, even if the values are manually reverted. Imports require strict UTF-8, no BOM/NUL and no duplicate values; malformed, duplicate and invalid-URL errors identify endpoint slot numbers without echoing endpoint contents, and failed imports retain the current editor. The editor shows the current UTF-8 manifest byte estimate and remaining budget while typing; the staged preview shows current and proposed byte sizes. Edit/remove/reorder endpoint slots before clicking **Download private text manifest**. Nothing is uploaded or saved to browser storage. Browser checks are convenience-only and do not prove an endpoint is isolated.

**Direct ordinal reorder:** Each endpoint row has an accessible **Slot NN** selector in addition to earlier/later buttons. Selecting another position moves the existing row and its original private input value directly to that slot; it never rewrites/canonicalizes the URL and preserves current row editing focus. All selectors are renumbered after insert/remove/move. A reorder counts as a real draft edit: any staged import/cleanup or outstanding Undo from a previously applied import is invalidated rather than allowed to overwrite newer order. The native original LabScenario gate continues to validate the resulting manifest.

**Guarded draft repair:** **Review draft cleanup** stages (but never silently applies) a first-occurrence-preserving, in-order proposal to remove blank slots and repeated identical HTTP(S) endpoint values and trim surrounding whitespace. The complete resulting candidate must pass the existing 1–16 / 16 KiB / duplicate / URL convenience checks or the original draft remains untouched. The current/proposed diff includes every original slot; counts disclose removed blank and repeated rows without sending any bytes out of the browser. A separate acknowledgement is mandatory before Apply or proposed private manifest download. Edits to the draft invalidate that staged cleanup; successful Apply offers a single guarded Undo until the first next edit. No canonicalization of URL host/path/query and no native authorization or isolation checks are performed.

**Display-only privacy mask:** Select **Hide endpoint values** to conceal existing endpoint inputs, staged current/proposed URL literals and pasted multiline text during a local screen review; choose **Show endpoint values** to edit again. If a download is requested while masked, the browser explicitly warns that the resulting PRIVATE text manifest still contains literal endpoint URLs. Masking is a local visual convenience only; it neither encrypts local HTML/browser memory, sanitizes the downloaded private file, hides earlier screenshots/clipboard content nor authenticates scope or permission.

**Strict async import revision fence:** Every actual editor keystroke, add/remove, ordinal reorder, imported Apply and Undo advances a local monotonic revision. Multi-file readers capture this revision *before* the first asynchronous file read and refuse the staged proposal if any edit occurred before completion, **even if the operator manually changed values back to their initial bytes**. Existing imports remain local, no file or endpoint bytes are persisted externally. This is UI concurrency integrity, not permission or scope attestation.

**Multi-file browser intake:** The file chooser now accepts **1–8 separate locally selected UTF-8 manifest files** (up to 16 KiB each) in a single staged import. Each source is decoded strictly and checked separately before entries are concatenated in the browser-provided file order; the complete selection must still fit the original single canonical 1–16 endpoint/16 KiB limit, with duplicate URLs across source files rejected. Choose existing-draft append or replace before selecting the files. A complete slot-by-slot private proposal is shown; no endpoint value changes until explicit Apply, and normalization/empty-slot losses require acknowledgement. Async file reads are cancelled if a newer import is started, or if draft contents/import mode change. No filenames, private paths, endpoint bytes or source file contents are sent out of browser memory, and no client identity or source order is authenticated. To retain per-file original SHA provenance and a source-ordinal board, use the native multi-source command described below; a downloaded browser result is still an unsigned plaintext PRIVATE manifest requiring native scope admission and mode 0600.

**Batch paste + guarded proposal:** **Paste multiple endpoints** opens an in-memory multiline composer for 1–16 lines. Choose **Replace entire current draft** or **Append after filled current slots**. A strict local UTF-8/size/duplicate/URL check is applied to the pasted batch and the complete combined candidate before any mutation; append refuses an invalid current draft, duplicate endpoints across batches, or more than 16 combined slots. Blank/comment lines and trimmed source whitespace are counted and require a separate acknowledgement before applying or downloading a canonical proposal; append also flags discarded empty draft slots. Preview always compares the entire current/proposed slots and never silently appends. Changes to existing slots after preview invalidate the pending proposal (also for file imports), so an outdated proposal cannot replace a newer editor. Apply retains one guarded Undo until the first further edit. Closing or applying clears the local paste area; nothing is uploaded or persisted by the browser. **Even an accepted pasted batch does not prove network isolation, identity, scope, consent, or authority.** The original pinned native policy admission remains mandatory.

Browser downloads cannot set file permissions. Before using the native CLI, move the downloaded file to a private directory and set mode `0600`. Use this PR branch (not the older source-only pinned ancestor), for example `git fetch origin chatgpt/lightup-assessment-launchpad-20261021-gpt6` followed by `git switch --detach FETCH_HEAD` in a disposable trusted checkout. The CLI refuses any modified original pinned validator or CLI bytes.

## Original validator source-pin admission

The native Launchpad opens each pinned original source file through no-follow directory/file descriptors, requires a bounded regular file, and rejects symlinks or metadata drift during the read. It checks the expected Git blob digest before importing the original URL and `LabScenario` validators, verifies those modules resolve to the expected repository paths, then re-reads all pinned source files and checks their digests again. Any missing, oversized, non-regular, drifting or changed source produces HOLD before a manifest handoff is accepted. These are local integrity checks, not a signed source identity, consent, authorization or release claim.

## Native no-browser PRIVATE manifest merge and reopen

Operators without a graphical browser can combine **two already private owner-owned mode-0600 text manifests** with the same original pinned lab URL and LabScenario scope policy. The additional `combine_manifest.py` command runs fully locally (no network, resolver, model, subprocess, assessment, consent or grant). The explicit mode is either `append` (retain all first entries, then all second entries; reject ANY duplicate or resulting >16 slots/16 KiB) or `replace` (use only the second list, requiring `--ack-replace`). No endpoint is silently dropped or deduplicated. Blank lines, comments, CRLF or whitespace require `--ack-normalization` before publication. The whole result is re-admitted through the original pinned validator.

Example, with two distinct local PRIVATE source files and an existing **empty** user-owned mode-0700 output directory, separate from both source trees:

    mkdir -m 700 ~/private-combined-manifest
    python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --mode append --output-dir ~/private-combined-manifest --explain-hold

**Multi-file lab batches (2–8 original sources):** `combine_manifest.py` now accepts up to six ordered `--more-manifest PRIVATE.txt` arguments after the original `--first-manifest` and `--second-manifest`. Each source remains an independently admitted current-user-owned mode-0600 regular file (no symlink, hard link or changed-file acceptance). In `append`, each source is retained in exact supplied order; in `replace`, only the first source is discarded (after `--ack-replace`), while all later sources are retained. The entire resulting batch must still fit 1–16 unique literal original-policy-admitted lab URLs and 16 KiB. Sources may not refer to the same exact path. Example with four distinct private files:

    python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --more-manifest ~/private-input-c/targets.txt --more-manifest ~/private-input-d/targets.txt --mode append --dry-run

**Explicit source curation (no original mutation):** During a 2–8-source batch, add one or more `--omit-source N` arguments where `N` is the original one-based source ordinal. The source is still independently opened and source-byte-bound; it contributes **zero** endpoint URLs to the new canonical result. The original files remain unchanged. An omitted source requires `--ack-omit` during publication or exact reopen, while a `--dry-run` only reports counts and the required acknowledgement (it never publishes). Duplicate/out-of-range omissions and selecting an empty final result fail closed. In `replace` mode, source 1 is already discarded and cannot also be omitted; `append` retains source 1 unless explicitly omitted. An omission creates a distinct PRIVATE schema-v3 source receipt containing **only** original source ordinals, counts, unsigned source SHA digests and omitted ordinals, and an updated scriptless PRIVATE HTML board showing retained/omitted rows and reindexed resulting slots. The v1 two-source and v2 multi-source no-omission receipt contracts are preserved. The operator must provide the same exact source files, ordering, mode, omission flags and acknowledgements for exact byte-for-byte reopen. This is a HUMAN planning selection, **never a substitute for original URL/LabScenario scope admission**: every retained endpoint is still checked by the original pinned gate.

Example:

    python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --more-manifest ~/private-input-c/targets.txt --omit-source 2 --mode append --dry-run

**PRIVATE per-slot HUMAN handoff:** Every multi-source (3–8 input files) or explicit omission plan now also creates `lightup-manifest-source-slots-private.csv`. For each source's originally declared local slot it reports only fixed-vocabulary original source ordinal, original slot ordinal, resulting global slot ordinal (blank for discarded sources), selection status and literal `REVIEW_ONLY`. This lets a HUMAN reviewer map a source file's slot number back to the combined workroom's slot number without distributing the actual URL, file path, source name, hashes or notes. The CSV remains 0600 in the original private output; small-group ordinal patterns may still be sensitive. The complete private bundle is exact-byte checked during read-only reopen, and the original two-source no-omission v1 artifacts remain unchanged. Earlier schema-v2 PRIVATE packets issued **before** the CSV handoff existed (canonical manifest + source-bound receipt + HTML board only) remain readable in `--verify-output` mode: the existing three files must each match the exact current regenerated bytes and original sources. This legacy read-only admission does **not** permit publishing a new incomplete packet; new multi-source output includes the PRIVATE source-slot CSV, and v3 omission packets require the complete current output shape. No source authenticity, real scope clearance, consent, grant, finding validity or authority is inferred.

**PRIVATE browser-readable source allocation board:** For a three-to-eight-source batch, the output also includes `lightup-manifest-source-board-private.html`. This scriptless, exact SHA-256-CSP pinned mode-0600 local HTML presents original source ordinals, declared endpoint counts, retained/discarded selection and resulting ordinal slot ranges. It does **not** include source filenames, paths, hashes, endpoint URLs or review text. Keep this file PRIVATE: small-group counts may still be sensitive. The complete three-file batch is checked during exact read-only reopen; two-source output remains the existing two-file v1 bundle without a new board. These are operator-selected slot ranges, not authenticated provenance, findings or permission.

Two-source receipts remain original schema v1, preserving existing reopen behavior. Three to eight sources create a PRIVATE schema-v2 receipt with an ordinal, endpoint count and unsigned exact byte SHA-256 for **each** original source; never endpoint values or input paths. Source order is supplied by the operator, **not authenticated chronology, consent, client ownership or verified scope**. Publication requires an empty private output directory, source re-admission directly before write and the same explicit normalization/replace acknowledgments. Exact read-only re-open requires all original source files in the same order. The complete preview-only or HUMAN-only workroom may be requested as before.

**Read-only rehearsal before publication:** The same inputs support `--dry-run` with no `--output-dir`, `--handoff-dir` or `--verify-output`; neither acknowledgment flag is required in read-only mode. It re-admits both owner-private sources through the original pinned lab scope gates and prints only fixed-vocabulary counts (first/incoming/retained/discarded/result) plus whether normalization and replacement acknowledgement will be required during real publication, without displaying endpoint URLs, input paths, source hashes or private notes. No output directories or files are touched. Example:

    python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --mode replace --dry-run --explain-hold

Only the **actual publication** requires `--ack-replace` for replacement and `--ack-normalization` for lossy comment/blank-line/whitespace changes. A dry-run is not execution authority, consent, proof of source identity or an authorization check for real targets. Unexpected source failures are converted to a redacted HOLD without printing raw exceptions.

Two exclusive no-overwrite owner-only files are created: `lightup-lab-targets.txt` (canonical actual PRIVATE endpoint URLs, mode 0600) and `lightup-manifest-combine-private.json` (PRIVATE unsigned input/output SHA-256 consistency digests and original-policy admission counts, no endpoint literals). Those digests are **not signatures, identity authentication or consent**; even the aggregate counts may identify small engagements. The CLI prints counts only, no URLs, paths or exception details. If validation fails, nothing is published. The output directory must not contain existing files.

Re-open later read-only against the same two unchanged source files, modes and acknowledgements:

    python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --mode append --output-dir ~/private-combined-manifest --verify-output --explain-hold

**One-command complete preview-only handoff:** Create a *second* separate empty mode-0700 directory `~/private-combined-preview` and add `--handoff-dir ~/private-combined-preview` to the original combine command. The CLI publishes the canonical 0600 combined source first, then directly calls the already-existing original-pinned `launchpad.run` to create all five private preview-only workroom files (manifest, source-bound unsigned receipt, scriptless HTML, display-only command, source-minimal counts). This does **not** execute the displayed command or contact any target. The two output directories and both input trees must be mutually separate. If the second publication fails, the first private combined manifest remains available for explicit recovery; there is **no two-directory atomic transaction**. For read-only verification, add the same `--handoff-dir` to the original `--verify-output` command: it re-admits both source manifests, both bundles and exact matching combined/handoff manifest bytes without publishing or executing.

**One-command complete HUMAN-only workroom:** Alternatively select `--workspace-dir ~/private-combined-human-workroom` (mutually exclusive with `--handoff-dir`). Create this as an independent *empty* mode-0700 directory before running. After privately combining and original-LabScenario-revalidating both manifests, the command invokes the **existing** `workspace.py` in-process. It constructs the entire original preview-only bundle, initial source-bound PRIVATE HUMAN worksheet and scriptless HTML follow-up, local browser worksheet editor, role-filterable routing inbox, source-minimal counts and PRIVATE landing page/guide in separate mode-0700 subdirectories containing mode-0600 files. None of the generated commands is executed; all HUMAN statuses are unauthenticated proposals. In contrast with the minimal preview, **this complete HUMAN workspace includes PRIVATE endpoint URLs and notes in files and must never be shared, served or deployed**. The workspace CLI also prints an unsigned source digest on the operator's own private terminal. For read-only reopen, use `--verify-output --workspace-dir` along with the exact original inputs/flags; this re-admits the original HUMAN workspace and binds the nested source manifest bytes back to the combined canonical manifest. Combining and workspace publication are intentionally distinct private steps, **not an atomic transaction across directories**: on workspace failure keep all partial workroom files private and do not use them as an admitted workroom. No authority, review approval, live action or HUMAN GO is inferred.

This enforces exact bytes and rejects extra/missing/modified PRIVATE output files. For the **next original-source-bound handoff**, use the resulting `~/private-combined-manifest/lightup-lab-targets.txt` as the `--manifest` input to `launchpad.py`, with a **new separate empty** user-owned mode-0700 output directory; the merge command never executes a preview command. All source-owner, security/privacy, exact-head CI, independently authenticated current client/operator consent with revocation-at-use and explicit HUMAN GO release gates remain untouched.

## PRIVATE offline change desk for two already saved combined manifests

### Multi-plan PRIVATE lab history desk (2–8 snapshots)

The standalone, networkless `manifest_history_desk.py` builds an operator-ordered review of **2–8 already saved PRIVATE combined-manifest bundles**. Every input is reopened through the original pinned lab URL/LabScenario policy and its exact canonical saved source/receipt/slot map admission. The script compares consecutive plans and also first-to-last literal endpoint equality, publishing a scriptless CSP-hashed **PRIVATE HTML transition table**, a PRIVATE machine-readable JSON with unsigned per-source SHA-256 digests, a PRIVATE numeric counts CSV, and a separate ordinal-only PRIVATE HUMAN follow-up CSV. A collapsible HTML review queue lists only changed per-plan slots (MOVED/REMOVED/ADDED), never treats a literal change as remediation or approval. The HTML and CSVs never contain URLs, source paths, file names, original notes or digests.

```sh
python3 assessment-launchpad/manifest_history_desk.py --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two --plan-dir ~/private-plan-three --output-dir ~/private-plan-history
python3 assessment-launchpad/manifest_history_desk.py --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two --plan-dir ~/private-plan-three --verify-output-dir ~/private-plan-history
```

### Private HUMAN stage editing — accessible browser studio or native CLI

Open `assessment-launchpad/history_review_editor.html` **locally**, with no server or network connection. This standalone, responsive editor has a strict SHA-256-hash CSP, no CDN, external assets, storage, telemetry, cookies, localStorage or fetch. Import the exact `lightup-manifest-history-review-queue-private.csv` emitted by the history desk. Review changed slot ordinals in a filterable table, assign one of six explicit HUMAN follow-up stages per row or to an expressly confirmed subset, undo the latest edit and download the complete original-order six-column PRIVATE CSV. No URL, original filename or source digest is displayed or exported; all review state remains transient in the browser. Even an empty original queue can be saved unmodified. Import rejects oversized (>64 KiB), malformed, duplicate or out-of-sequence source slot rows; the native verifier still owns final original-source validation.

Browser downloads cannot enforce POSIX file mode: move the downloaded CSV into a dedicated private `0700` answers folder and use `chmod 600` before calling `manifest_history_response.py`. Never open/share this private CSV as a public preview.

**Browserless alternative:** use `manifest_history_editor.py` to publish the same exact PRIVATE CSV directly as a mode-`0600` file, with no manual file permissions or row editing. Its `--stage N:STAGE` selects the Nth (1-based) original changed-slot row, retains the entire source order and all immutable identity columns, and changes **only** that row's HUMAN stage. It requires original saved bundles and exact private history, a new separate empty owner-owned mode-`0700` answers directory, and supports read-only reopen with the same source and stage choices:

```sh
mkdir -m 700 ~/private-plan-answers
python3 assessment-launchpad/manifest_history_editor.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --stage 1:NEEDS_CONTEXT --stage 2:IN_REVIEW \
  --output-dir ~/private-plan-answers
python3 assessment-launchpad/manifest_history_response.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --answers-dir ~/private-plan-answers --output-dir ~/private-human-return
```

The browser and CLI are two **alternative** ways of preparing the original ordinal queue. Neither establishes real chronology, genuine client/operator authority, true scope provenance or permission to scan; a PRIVATE HUMAN stage is never remediation proof or a security release gate.

### PRIVATE HUMAN review return for manifest-history changes

The optional standalone `manifest_history_response.py` completes the offline loop for the history queue. The operator copies **only** `lightup-manifest-history-review-queue-private.csv` from an original saved PRIVATE history bundle to a **separate private 0700 answers directory** (retaining the exact filename and mode-0600 ownership), edits ONLY its `human_stage` column, and selects one of the literal statuses `FOLLOW_UP_REQUIRED`, `NEEDS_CONTEXT`, `IN_REVIEW`, `QUESTION_PREPARED`, `PARKED` or `HUMAN_REVIEWED`. All plan-pair, change, source slot and destination slot columns must remain byte-literal CSV values and in the original source order. No notes, formulas, additional rows or unrecognized statuses can be imported.

```sh
python3 assessment-launchpad/manifest_history_response.py --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two --history-dir ~/private-plan-history --answers-dir ~/private-plan-answers --output-dir ~/private-human-return
python3 assessment-launchpad/manifest_history_response.py --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two --history-dir ~/private-plan-history --answers-dir ~/private-plan-answers --verify-output-dir ~/private-human-return
```

**One-command HUMAN return (no answers directory):** `manifest_history_response.py` additionally accepts explicit repeatable `--stage ROW:STAGE` in place of `--answers-dir`. This derives every untouched row straight from the originally admitted history queue, applies only explicitly chosen HUMAN stage labels, and creates the complete three-file source-bound PRIVATE return in one directory. For example:

```sh
mkdir -m 700 ~/private-direct-human-return
python3 assessment-launchpad/manifest_history_response.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --stage 1:NEEDS_CONTEXT --stage 2:IN_REVIEW \
  --output-dir ~/private-direct-human-return
```

The optional direct-stage route and the imported `--answers-dir` route are mutually exclusive. The native output has the same strict original-source read-only reopen behavior (use identical `--stage` values with `--verify-output-dir`); both produce unsigned REVIEW_ONLY HUMAN records. Reviewers may instead use the accessible local browser studio or the native 0600 queue publisher before running the original return CLI.

Before HUMAN return publication, the native CLI re-verifies the saved history against the original pinned policy and source manifests, strictly matches the complete edited CSV against the ordinal queue, and re-opens all inputs. It publishes three exclusive mode-0600 files in a separate empty owner-owned 0700 directory: source-bound PRIVATE JSON containing unsigned source and answer hashes, scriptless CSP-pinned PRIVATE HUMAN status HTML (no URLs/paths/hashes) and an aggregate stage-count PRIVATE CSV. The previous source and HUMAN answer files are never overwritten. The stages are non-authorizing **human work notes only**: even `HUMAN_REVIEWED` is not approval, valid consent, verified remediation, revocation clearance or release authority. No active targets, scanner, DNS, model, auth or original source-owner code is touched.

### Browse open HUMAN work from the native CLI, without disclosing endpoint values

`manifest_history_next_round.py --show-pending` reads the same exact original PRIVATE source plans, their saved source-bound history and **1–7 ordered saved HUMAN returns**, then prints only the 1-based original queue row ordinal, plan-pair ordinals, literal ADDED/REMOVED/MOVED tag and last HUMAN follow-up stage for rows marked FOLLOW_UP_REQUIRED, NEEDS_CONTEXT, IN_REVIEW or QUESTION_PREPARED. This helps an operator choose explicit `--stage ROW:STAGE` values for the next round without opening a private endpoint manifest, copying paths into logs or manually counting CSV lines.

```sh
python3 assessment-launchpad/manifest_history_next_round.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --round-dir ~/private-human-return-one \
  --show-pending
```

The command rejects any edit, output or preview flags mixed with `--show-pending`, creates no files and never executes an assessment. It shows all active HUMAN follow-up labels in original queue order, including zero rows. PARKED or HUMAN_REVIEWED are omitted from the active worklist but neither state represents remediation or clearance; authentic source-owner and consent/security/HUMAN GO gates remain mandatory.

### One-command next HUMAN round with optional timeline and delta

For an existing exact 1–7-round local HUMAN chain, `manifest_history_next_round.py` now joins the source-bound native operations into **one explicit offline command**. It re-admits the original PRIVATE plan history and all prior v1/v2 HUMAN rounds, checks the unsigned previous-round linkage, carries forward unmodified HUMAN stages and changes only selected `--stage ROW:STAGE` choices. It then creates a **new PRIVATE HUMAN return** and can independently generate the two-round stage comparison and an updated 2–8-round timeline with a follow-up CSV. No original source or prior HUMAN round is overwritten.

```sh
mkdir -m 700 ~/private-human-next ~/private-human-next-delta ~/private-human-next-timeline
python3 assessment-launchpad/manifest_history_next_round.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --round-dir ~/private-human-return-one \
  --stage 2:NEEDS_CONTEXT --stage 3:IN_REVIEW \
  --output-dir ~/private-human-next \
  --delta-dir ~/private-human-next-delta \
  --timeline-dir ~/private-human-next-timeline
```

The same command also accepts a complete private browser-edited six-column CSV via `--answers-dir` **instead of** `--stage`. This completes the browser-to-native-to-timeline workflow in one call, with the original previous round retained and an explicit acknowledgement before importing *all* replacement HUMAN stages:

```sh
mkdir -m 700 ~/private-human-next ~/private-human-next-delta ~/private-human-next-timeline
python3 assessment-launchpad/manifest_history_next_round.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --round-dir ~/private-human-return-one \
  --answers-dir ~/private-edited-answers --ack-csv-stage-replace \
  --output-dir ~/private-human-next \
  --delta-dir ~/private-human-next-delta \
  --timeline-dir ~/private-human-next-timeline
```

To preview this exact edited CSV, use `--dry-run` and omit **all** output directories and the acknowledgement flag. The source-bound native return still reopens the original plan, history, prior HUMAN return and private browser-edited answers; the browser itself cannot establish original-source authenticity or permissions.

Use the same original inputs with `--dry-run` and **no output directories** to see only changed-row counts and the next HUMAN round ordinal; no files are published. To reopen all three finished PRIVATE outputs without rewriting them, repeat the original arguments with `--verify-output`. Every requested destination must exist, belong to the current user, have mode `0700`, and be separate from each other and all original source trees; publication uses mode-`0600` exclusive files.

**These are independent PRIVATE publications, not a single atomic cross-directory transaction.** If later delta or timeline publication fails, the already published HUMAN return is still only an isolated unsigned PRIVATE review artifact; it is not a completed combined packet and cannot authorize any release or assessment. The stage vocabulary is non-authorizing, and source-owner/privacy/security, independently authenticated client/operator consent (including action-time revocation), required CI and explicit HUMAN GO remain unchanged.

### Read-only HUMAN stage preview before publishing

`manifest_history_response.py --dry-run` can now reopen the exact original PRIVATE history and proposed HUMAN stage source without writing an output file. It reports only the number of original changed-slot rows, the number of HUMAN status changes relative to the original or preceding saved return, whether a prior source-bound round exists and whether the full-CSV stage replacement will require acknowledgement. It does not disclose endpoint values, private paths, notes, source hashes, client identity or authorization data. The **preview does not authorize publication** and can be used before approving a full CSV replacement:

```sh
python3 assessment-launchpad/manifest_history_response.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --continue-from-return-dir ~/private-human-return-one \
  --answers-dir ~/private-edited-answers --dry-run
```

For publication, use the same inputs with a separate empty owner-private `--output-dir` and `--ack-csv-stage-replace`. Preview never substitutes for the strict native original-source gate, current client/operator permission or the original security/privacy/HUMAN GO gates.

### Resume HUMAN review through the offline browser, without losing the source-bound chain

The local standalone `history_review_editor.html` now accepts an **optional saved PRIVATE HUMAN return JSON** after the original source history queue CSV is imported. Select exactly `lightup-manifest-history-human-return-private.json` from the previously saved v1/v2 HUMAN return. The browser checks the strict return envelope, false authority flags, row count, original ordinal identities and stage counts, and then asks for explicit confirmation before replacing its current in-memory HUMAN stage labels. It does not contact a server, store data, validate digital signatures or independently authenticate the original plan history. The original native source read/reopen remains mandatory.

After reviewing and exporting the complete six-column PRIVATE CSV, store the file in an owner-only `0700` answers directory with mode-`0600`. To **continue** the original saved HUMAN round (rather than accidentally create a new v1 root), pass the existing return directory along with the edited CSV and explicit full-stage-replacement acknowledgement:

```sh
mkdir -m 700 ~/private-human-return-next
python3 assessment-launchpad/manifest_history_response.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --continue-from-return-dir ~/private-human-return-one \
  --answers-dir ~/private-edited-answers --ack-csv-stage-replace \
  --output-dir ~/private-human-return-next
```

This writes a fresh v2 HUMAN return, pins the old source-bound JSON digest and imports the exact original-order CSV row identities. **CSV stage replacement is all-or-nothing**, so the acknowledgement must be explicit: without it the CLI fails closed to prevent silent resetting of prior stage labels. The browser does not produce approval, remediation proofs, source authenticity, verified consent or HUMAN GO. Running the same options with `--verify-output-dir` reopens the completed output without writing.

### Continue an existing PRIVATE HUMAN round without resetting prior work

`manifest_history_response.py` can now **carry forward every previous HUMAN status** from a separately saved and strictly admitted PRIVATE return, and change only the specified rows in a new private result:

```sh
mkdir -m 700 ~/private-human-return-next
python3 assessment-launchpad/manifest_history_response.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --continue-from-return-dir ~/private-human-return-one \
  --stage 3:NEEDS_CONTEXT --stage 5:HUMAN_REVIEWED \
  --output-dir ~/private-human-return-next
```

The original source plans/history and **all three files** of the prior HUMAN return are read without mutation and matched to the same original ordinal source list. Every untouched stage is carried forward; duplicates/unknown stages/missing original rows fail closed. This continuation uses a new `lightup.private-manifest-history-human-return.v2` PRIVATE receipt containing the **unsigned SHA-256 of the exact prior return JSON** plus an explicit unsigned-local-consistency label; original v1 returns remain readable. It is never a signed review chain or identity proof. Exact `--verify-output-dir` accepts the same continuation source and stages to reopen a new PRIVATE result without writing. Source and destination trees must be separate.

The original source/auth/consent/revocation/HUMAN GO requirements are unchanged. A copied status, including `HUMAN_REVIEWED`, is always a non-authorizing HUMAN work note and never authorizes assessment or verifies remediation.

### Full PRIVATE HUMAN review timeline across 2–8 chained rounds

`manifest_history_rounds.py` extends the two-round comparison into an ordered **2–8-round HUMAN review timeline**, without rerecording original findings or contacting targets. It re-admits all original PRIVATE combined-plan bundles and their saved source-bound history, then independently reopens every complete PRIVATE HUMAN return (receipt, scriptless print HTML and counts). The **first round must be the original v1 return**; each subsequent v2 continuation must contain the exact unsigned SHA-256 of the immediately preceding return. Missing rounds, incorrect ordering and altered saved source bytes fail closed. This verifies **local byte consistency only**, not the operator's identity, trustworthy chronology or approval.

```sh
mkdir -m 700 ~/private-human-timeline
python3 assessment-launchpad/manifest_history_rounds.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --round-dir ~/private-human-return-one \
  --round-dir ~/private-human-return-two \
  --round-dir ~/private-human-return-three \
  --output-dir ~/private-human-timeline
```

The separate empty owner-private 0700 output directory receives four exclusive mode-0600 artifacts: `lightup-human-timeline-private.json` (source-bound unsigned per-round digests, original ordinal identities and all stage transitions), `lightup-human-timeline-private.html` (a scriptless SHA-CSP-pinned, horizontally scrollable HUMAN dashboard with current-stage workload cards, an expandable active HUMAN follow-up queue and the full stage-by-round table, without URLs, paths, file names or source hashes) and `lightup-human-timeline-counts-private.csv` (per-round HUMAN stage and transition counts), plus `lightup-human-timeline-followups-private.csv` (an ordinal-only PRIVATE next-review queue containing current FOLLOW_UP_REQUIRED, NEEDS_CONTEXT, IN_REVIEW or QUESTION_PREPARED stages, with original row numbers and the number of local HUMAN stage changes). PARKED and HUMAN_REVIEWED are not included in this active follow-up queue; neither state indicates a fixed finding or validated completion. Reopen without writing by replacing `--output-dir` with `--verify-output-dir` and keeping **exactly** the same original plan/history/round arguments. Even an all-HUMAN_REVIEWED series proves neither remediation nor approval; the source-owner, independent security/privacy, actual separate authenticated client/operator consent, action-time revocation and HUMAN GO gates remain intact. No scanning, DNS, subprocess, model, grant or target execution is performed.

### Compare two PRIVATE HUMAN follow-up rounds on the same manifest history

`manifest_history_followup.py` completes the offline multi-round workflow. Given **exactly the same original ordered saved plans and original PRIVATE history**, it reopens two separately saved three-file HUMAN return bundles, validates their original row identities, byte-canonical private JSON, exact scriptless HTML and counts, source-history digest binding and all false authority flags. The inputs may be returned through either the stage CLI or previously edited PRIVATE CSV; locally stored input digests remain unsigned and cannot independently prove who edited the responses.

```sh
mkdir -m 700 ~/private-human-stage-delta
python3 assessment-launchpad/manifest_history_followup.py \
  --plan-dir ~/private-plan-one --plan-dir ~/private-plan-two \
  --history-dir ~/private-plan-history \
  --before-return-dir ~/private-human-return-one \
  --after-return-dir ~/private-human-return-two \
  --output-dir ~/private-human-stage-delta
```

The resulting separate PRIVATE `0700` directory contains three no-overwrite mode-`0600` files: `lightup-human-history-stage-delta-private.json` with unsigned digests and original row-bound HUMAN stage transitions, a scriptless SHA-CSP HTML follow-up table without URLs/paths/hashes, and a stage counts CSV without targets. It reports **only literal HUMAN stage changes** (including zero changes) and does not infer improvement, fixes, risk, validation, approval or genuine chronological ordering. Use the same original plans/history/rounds plus `--verify-output-dir` instead of `--output-dir` for exact read-only reopen. Every original lab authority and release gate remains unchanged.

**One-command combine + history:** `combine_manifest.py` also accepts 1–7 repeated `--history-prior-dir` values plus one `--history-output-dir` to append its newly published combined plan as the final historical snapshot. It admits all prior saved PRIVATE bundles before publication; the new plan and history are written in **separate private transactions**. `--verify-output` reopens both without writing. This optional history may be requested alongside the independent change-desk and offline HUMAN workspace, but every destination must be separate from all source and output trees.

```sh
python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --mode append --output-dir ~/private-plan-three --history-prior-dir ~/private-plan-one --history-prior-dir ~/private-plan-two --history-output-dir ~/private-plan-series
```

The destination must be a **different existing, empty, owner-owned 0700 directory**; the four mode-0600 files are exclusive/no-overwrite and admit exact source-bound read-only reopen. Operator ordering does **not** establish trustworthy chronology, and neither local hash equality nor a missing endpoint means a vulnerability is fixed or any action is approved. Keep all four files PRIVATE; even anonymous ordinal counts may be commercially sensitive. No live scan, DNS, model, original source ownership changes, consent, revocation or HUMAN GO is performed.

### One-command saved-plan comparison (new optional offline step)

The native `combine_manifest.py` now optionally generates the same **PRIVATE read-only literal change desk** while constructing a new combined plan. Supply `--change-before-dir` for a **previously saved and already admitted PRIVATE combine bundle** and `--change-output-dir` for a **third, empty owner-owned 0700 directory**:

```sh
python3 assessment-launchpad/combine_manifest.py --first-manifest ~/private-input-a/targets.txt --second-manifest ~/private-input-b/targets.txt --mode append --output-dir ~/private-combined-next --change-before-dir ~/private-combined-previous --change-output-dir ~/private-combined-delta
```

The source is inspected before publication and the saved *new* combined packet is independently admitted again before comparison. The difference artifacts are the existing `lightup-private-manifest-delta.json` and scriptless `lightup-private-manifest-delta.html`, with ordinal-only UNCHANGED/MOVED/REMOVED/ADDED descriptions. No endpoint, note, input path or target action appears in the comparison. To reopen all three bundles **without writing**, repeat the exact inputs with `--verify-output`; the previous and new combined bundles and the private change report must still match. A prior combine bundle (v1/v2/v3), current outputs, change output, optional handoff/workspace and source trees must remain separate. `--dry-run` does not accept comparison/output flags. Source and change outputs are separate private transactions: an error in later comparison may leave the earlier combined packet PRIVATE but must not be treated as a complete handoff. This is unsigned, planning-only local consistency, **not proof of original source authenticity, assessment authorization, consent, revocation status, remediation or HUMAN GO**.

A separate additive `assessment-launchpad/manifest_change_desk.py` reads **two previously saved** owner-only PRIVATE combined-manifest bundle directories. It admits exactly the original v1 (two files), v2 (three-file legacy or complete current) or v3 (complete current) bundle file names via no-follow mode-0700 directory / mode-0600 file reads. It rechecks the canonical literal manifest, the unsigned stored canonical manifest digest and the **original pinned** URL/`LabScenario` scope policy, plus the saved PRIVATE multi-source HTML/slot-map bytes where present. It cannot authenticate original upstream source file identities (these source files are not necessarily available here); hashes are **local unsigned consistency, never consent or scope authority**.

The human manually selects before/after order (not authenticated chronology). The desk compares 1–16 literal endpoint URL values internally and emits only ordinal-only rows tagged `UNCHANGED`, `MOVED`, `REMOVED` or `ADDED`. It does not embed raw URLs, filenames, source paths or HUMAN notes in the new artifacts. A changed position is not a vulnerability and a removed endpoint is **not** proof of a fix.

Create an independent **empty**, owner-owned mode-0700 directory and run:

    mkdir -m 700 ~/private-lab-manifest-change
    python3 assessment-launchpad/manifest_change_desk.py --before-dir ~/private-original-lab-plan --after-dir ~/private-updated-lab-plan --output-dir ~/private-lab-manifest-change

Two no-overwrite PRIVATE mode-0600 artifacts appear: `lightup-private-manifest-delta.json` (strict source-bound unsigned SHA256 manifest digests and per-slot ordinal changes; all authority flags false) and `lightup-private-manifest-delta.html` (scriptless exact-CSP local printable change desk). Only counts appear on the terminal. Small-group count and slot transitions can still reveal sensitive patterns; do not publish these outputs. For a **read-only exact reopen**, use the same original two source directories with `--verify-output-dir ~/private-lab-manifest-change` instead of `--output-dir`; missing, modified or unexpected files fail closed. No DNS, model, network, target, command execution, grant, consent, scan or release occurs. Source-owner/privacy/security reviews, original CI, current authenticated independent consent with action-time revocation and HUMAN GO remain mandatory.

## Native validator-backed handoff

Requires a checkout of this launchpad PR branch, which contains both `assessment-launchpad/` and the original source files at the frozen source pin, with the existing project Python dependencies. Checking out the pinned ancestor commit **alone will not work** because that older commit does not contain the launchpad. Create an owner-only output directory separate from the manifest directory:

```bash
chmod 600 ~/Downloads/lightup-lab-targets.txt
mkdir -m 700 ~/private-lab-launchpad-output
python3 assessment-launchpad/launchpad.py \
  --manifest ~/Downloads/lightup-lab-targets.txt \
  --output-dir ~/private-lab-launchpad-output
```

The CLI checks the Git blob hashes of the pinned original `cli.py`, `labrun.py`, `labeval.py`, `scope.py` and `models.py` before loading the original `_admit_explicit_lab_url` and `LabScenario`. `LabScenario` invokes the original isolated loopback/private-lab `ScopePolicy`. No DNS resolution or target connection is made. If a local admission returns HOLD, `--explain-hold` prints only the curated reason; filesystem paths, endpoint values and raw exception details remain withheld. This flag does not relax or bypass any admission gate. The same opt-in diagnostic is available on `workspace.py`, `review_desk.py`, `editor.py`, `routing.py`, `advance.py`, `compare_review.py`, `history.py`, `action_handoff.py`, `action_selection_compare.py`, `role_handoff.py`, `role_return.py`, `role_return_conflicts.py` and `role_return_reconcile.py` for consistent troubleshooting across the offline HUMAN workflow.

The command requires an owner-owned input regular file with mode `0600`, no symlink/hard-link alias, bounded stable contents (16 KiB), and 1–16 distinct endpoints. The output directory must already exist, be owned by the current user and have mode `0700`. Outputs are exclusive no-overwrite files with mode `0600`; failed bundle publication removes newly created outputs.

The output directory receives five private artifacts:

- `lightup-lab-targets.txt` — canonical one-URL-per-line manifest, suitable for the original CLI's `--targets-file` argument.
- `lightup-lab-plan-receipt.json` — PRIVATE source-bound receipt with input/canonical manifest SHA-256, endpoint count, pinned original CLI/validator sources, and SHA-256 of the generated HTML/command; no endpoint values.
- `lightup-lab-plan-handoff.html` — scriptless, CSP-pinned handoff showing the exact preview command, counts and private paths; endpoint values are not embedded.
- `lightup-lab-preview-command.txt` — exact shell-quoted display-only command using `--preview-only`.
- `lightup-lab-minimal-summary.json` — separate privacy-minimal, counts-only `REVIEW_ONLY` stakeholder handoff with no endpoint literals, source paths, source hashes or identifying records; local validator checks are not permission.

The command is generated but **never executed**. A human may inspect it and, separately, run the existing CLI with `--preview-only`; that original mode validates the same input without running an assessment. The future preview output path is intentionally not created by the launchpad.

## Safety boundaries

All receipt flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, `release_allowed=false`. Source content/identity, client identity, scope approval, operator consent and HUMAN GO are each explicitly unauthenticated/false. The receipt does not authenticate source identity, client identity, scope approval or consent. No subprocess, assessment, model call, target interaction, DNS, network request, grant, scan, remediation, retest or release occurs. Original exact-head CI, source-owner/security/privacy review, authentic separate client/operator consent, action-time revocation and HUMAN GO remain mandatory.

## Offline reopen and handoff integrity

On the same verified PR checkout (and Python interpreter), re-open the generated packet without running its displayed command:

```bash
python3 assessment-launchpad/launchpad.py --verify-output-dir ~/private-lab-launchpad-output
```

Reopen demands the original five owner-owned single-link mode-0600 regular files in an owner-owned mode-0700 directory. It checks bounded stable bytes, the canonical manifest and ordinals, exact known receipt schema and literal-false authority flags, the pinned original CLI/scope sources, the stored HTML/command content hashes, and exact expected `--preview-only` command. It does not fetch outside the local workspace, run a subprocess, create an output file, authenticate the original source producer, verify client scope authority or prove that a target was assessed. The digest hashes are **unsigned consistency checks only**: an attacker controlling both payload and receipt could rewrite both. Mismatch fails closed with HOLD and no output.

The separate minimal summary is deterministically reconstructed during reopen; any extra source identifiers, paths, hashes, or edited authority statements make the bundle fail closed. It is a low-detail planning artifact, **not proof of confidentiality, anonymous identity, validated scope or assessment**. Its endpoint count may still be sensitive in a small engagement.


## PRIVATE HUMAN follow-up desk

A second source-bound offline workflow turns one completed five-file Launchpad preview packet into a PRIVATE, human-only review desk. It does not execute its preview command, authorize any asset, perform network requests, or assess any target.

Create a new, separate directory owned by the current user with mode 0700 (e.g., mkdir -m 700 ~/private-lab-human-round-1). Then run:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --output-dir ~/private-lab-human-round-1

The desk first reopens all five original files through the pinned original URL/isolated-lab scope validator. It creates four owner-only, no-overwrite mode-0600 files:
- lightup-lab-human-private.json: a source-byte-bound per-slot HUMAN planning worksheet. Only ordinal slots, stages, roles and up to 400-character notes may be edited. All authority, consent, dispatch and release flags remain false.
- lightup-lab-human-private.html: a CSP-pinned, scriptless printable workroom. **Contains the original endpoint URLs and private notes. Never publish or host it.**
- lightup-lab-human-counts.json: counts by fixed stage and role. Excludes endpoints, identifiers, paths, hashes and notes.
- lightup-lab-human-counts.csv: the same fixed-vocabulary counts for offline planning, no source or note values.

The initial worksheet assigns NEEDS_INPUT and UNASSIGNED to every original endpoint slot. Human stages are limited to NEEDS_INPUT, HUMAN_REVIEW and FOLLOW_UP; there is intentionally no APPROVED, CLEARED or DONE state. Neutral role choices are UNASSIGNED, LAB_OPERATOR, SCOPE_OWNER, SECURITY_REVIEWER and PRIVACY_REVIEWER.

To record a subsequent HUMAN follow-up, manually edit only the stage, role and note values in a copy of the owner-private JSON worksheet. Do not change its original source fingerprint, slot ordinals or false authority flags. Make a new empty owner-only 0700 directory and run:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --output-dir ~/private-lab-human-round-2

Strict JSON duplicate-key rejection, source fingerprint binding, exact original endpoint count and ordered slots, neutral stage/role schema, and owner/mode/no-link bounded stable reads apply before publication. Existing rounds are not overwritten. To re-open a completed review round read-only, revalidate against the SAME original packet:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --verify-review-dir ~/private-lab-human-round-2

This checks the four output artifacts against the canonical worksheet and original-source manifest bytes; hashes here are UNSIGNED LOCAL CONSISTENCY ONLY. The aggregate handoffs are low-detail, not a promise of statistical anonymity in small engagements. HUMAN notes never become security findings, client approval, remediation proof or a scan permit. All existing source-owner, hosted/permanent named VPS CI, independent security/privacy review, distinct authenticated client/operator consent with action-time revocation, and HUMAN GO gates remain mandatory.


### Guided local HUMAN review (no JSON editing required)

Use an interactive terminal instead of manually editing the worksheet:

    mkdir -m 700 ~/private-lab-human-guided
    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --interactive --output-dir ~/private-lab-human-guided

The interactive mode shows ONLY source ordinals (never the endpoint URLs), a fixed menu for stage and reviewer role, and the length—not the content—of any previous note. Enter a free-text note through a non-echoing terminal prompt. Enter retains the current value and a single hyphen clears an old note. Nothing is stored in shell history. A refused value or interrupted session cannot publish a partial new round.

To continue an older round interactively, add the --responses argument pointing at that old round's private worksheet and choose another distinct empty output folder. All exact-source and worksheet-validation protections still apply before and after editing. The HTML and JSON artifacts remain **private unencrypted files on disk**, regardless of the non-echoing terminal input. The absence of actual authority/consent/HUMAN GO still applies.


## Original-source-bound HUMAN round comparison

Compare two manually selected, already-created PRIVATE HUMAN review rounds without revealing their original endpoint URLs or private notes in the resulting handoffs:

    mkdir -m 700 ~/private-lab-human-changes
    python3 assessment-launchpad/compare_review.py --bundle-dir ~/private-lab-launchpad-output --before-dir ~/private-lab-human-round-1 --after-dir ~/private-lab-human-round-2 --output-dir ~/private-lab-human-changes

The comparator first reopens the original five-file packet through the frozen original validators, admits both complete four-file HUMAN rounds by private no-follow reads, checks each JSON against the exact original source bytes and regenerates the rest of the original HUMAN packet to detect drift. It requires two distinct source directories and does not mutate their contents.

The new exclusive mode-0600 artifacts inside the owner-only mode-0700 output directory are:

- lightup-lab-human-delta-private.html — scriptless CSP-pinned ordinal-by-ordinal follow-up history (stage and reviewer-role transition and whether a private note changed), without original endpoint values, notes, hashes or paths.
- lightup-lab-human-delta-counts.json — totals of changed slots, stage/role/note changes, plus stage and role distributions before and after. No per-slot identifiers or original source values.
- lightup-lab-human-delta-counts.csv — the equivalent counts for HUMAN workload reporting.

Read-only reopen against the SAME original packet and two original HUMAN rounds:

    python3 assessment-launchpad/compare_review.py --bundle-dir ~/private-lab-launchpad-output --before-dir ~/private-lab-human-round-1 --after-dir ~/private-lab-human-round-2 --verify-delta-dir ~/private-lab-human-changes

The ordering of the two supplied rounds is manually selected, not authenticated chronology. These changes do not prove finding resolution, client scope, completion, consent, verified identity, a scan, release or HUMAN GO. Any locally consistent data remains UNSIGNED. Never expose the PRIVATE outputs to a web server; continue to apply the original release gates.


## Portable PRIVATE browser editor for HUMAN worksheets

A HUMAN reviewer can now edit status, fixed reviewer role and private notes directly in the browser without entering values into raw JSON or a terminal. The new standalone editor is **produced offline from a previously admitted original Launchpad packet and one owner-private HUMAN worksheet**. It does not embed endpoint URL values, call external services, store anything in browser storage, or execute a preview/assessment. It DOES embed the PRIVATE worksheet and notes, so keep this HTML owner-only and never serve/host it.

    mkdir -m 700 ~/private-lab-human-editor
    python3 assessment-launchpad/editor.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --output-dir ~/private-lab-human-editor

Open the mode-0600 file lightup-lab-human-editor.html locally in the browser. This is a single-file app with SHA-256 CSP-pinned script and styles, no unsafe-inline, no dependencies or external network. Change the HUMAN stage/role and note fields for source ordinals, then explicitly click **Download edited PRIVATE HUMAN JSON**. Original source digest and literal-false authority fields are carried unchanged, with no endpoint values.

Browser downloads do not enforce private permissions. Move the newly downloaded lightup-lab-human-private.edited.json to a separate current-user-owned mode-0700 local directory and set its file permissions to mode 0600 before native import. Native import remains authoritative:

    mkdir -m 700 ~/private-lab-human-browser-round
    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-import/lightup-lab-human-private.edited.json --output-dir ~/private-lab-human-browser-round

To verify the original generated editor's bytes again, with the unchanged original Launchpad packet and source HUMAN worksheet:

    python3 assessment-launchpad/editor.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --verify-editor-dir ~/private-lab-human-editor

Native readmission rejects new fields, duplicate JSON keys, changed ordinals, changed source digests, affirmative authority claims, untrusted control/bidi marks and source drift. The local browser editor is a convenience for HUMAN self-report only; its download is NOT approval, consent, scope attestation, clearance, target access or verified original evidence. Security/privacy, separate authentic consent and revocation, required CI and HUMAN GO remain independent gates.


## One-command PRIVATE HUMAN assessment workspace

The native workspace.py composes the original Launchpad, a blank HUMAN review round, and the offline browser editor in one complete owner-private source-bound workspace.

Prepare a mode-0600 original manifest in a separate private directory and a NEW empty mode-0700 output root. Launch:

    mkdir -m 700 ~/private-lab-whole-workspace
    python3 assessment-launchpad/workspace.py --manifest ~/private-input/lab-endpoints.txt --workspace-dir ~/private-lab-whole-workspace

No subprocess, DNS, HTTP request, model, lab assessment, dispatch or permission request is executed. The orchestrator invokes the existing pinned original validator/source admission and native Launchpad, review desk and hash-pinned offline browser editor entirely in process. It creates owner-private mode-0700 subdirectories:
- launchpad: all five original 0600 manifest/receipt/preview artifacts and exact display-only --preview-only command.
- human-round-01: initial non-authorizing NEEDS_INPUT/UNASSIGNED HUMAN slots, private scriptless read-only HTML view, source-free stage/role count JSON/CSV.
- human-editor: the portable self-contained PRIVATE HTML to edit a source-bound HUMAN worksheet locally and explicitly download revised PRIVATE JSON.
- START-HERE-PRIVATE.txt: a mode-0600 guide and unsigned original source digest. This guide is PRIVATE; never publish it.

The root directory MUST be empty, current-user owned and mode 0700; each subdirectory is exclusively created at mode 0700 and each file at mode 0600. The original input directory must be separate and never nested inside the output workspace. A failure leaves any intermediate files strictly private and explicitly invalid: never accept them as an approved, complete or deployable workspace.

Reopen the entire original packet using the original five-file and source gates, complete HUMAN round, editor and guide verification, with no writes:

    python3 assessment-launchpad/workspace.py --verify-workspace-dir ~/private-lab-whole-workspace

For changed HUMAN responses, download from human-editor/lightup-lab-human-editor.html, move the download to a separate owner-only mode-0700 input directory, chmod 600 the JSON, then use review_desk.py --responses with a NEW private output directory. Compare separately admitted HUMAN rounds via compare_review.py. No claim of authorship, identity, consent, valid scope, completed review, cleared risk, remediation or HUMAN GO is possible from this workflow.


## Source-bound PRIVATE HUMAN role inbox

The separate native routing.py turns one already-produced, exactly admitted original PRIVATE HUMAN round into a role-specific human follow-up queue. Original source bundle and HUMAN round are re-opened and revalidated before publication. This is not a scan or assignment of verified consent.

    mkdir -m 700 ~/private-lab-role-inbox
    python3 assessment-launchpad/routing.py \
      --bundle-dir ~/private-lab-launchpad-output \
      --round-dir ~/private-lab-human-round-2 \
      --role SECURITY_REVIEWER \
      --stage FOLLOW_UP \
      --output-dir ~/private-lab-role-inbox

Filter options: --role ALL or one admitted HUMAN role; --stage ALL or NEEDS_INPUT, HUMAN_REVIEW or FOLLOW_UP. All outputs are no-overwrite, mode 0600 files in a distinct owner-only mode-0700 directory:
- lightup-lab-human-routing-private.html: private scriptless role-specific HUMAN inbox, sorted by role/stage/original slot, including original local endpoint URLs and HUMAN notes. NEVER share/host.
- lightup-lab-human-routing-private.csv: PRIVATE fixed-vocabulary slot, stage, role and note-length rows. It does not include endpoint values or note text. It is explicitly not anonymous.
- lightup-lab-human-routing-counts.json: separate low-detail role/stage counts excluding source values, paths, digest and HUMAN note text. Counts may still reveal information in small engagements.

Read-only reopen, against the EXACT same original bundle and original HUMAN round:

    python3 assessment-launchpad/routing.py \
      --bundle-dir ~/private-lab-launchpad-output \
      --round-dir ~/private-lab-human-round-2 \
      --role SECURITY_REVIEWER \
      --stage FOLLOW_UP \
      --verify-routing-dir ~/private-lab-role-inbox

The one-command workspace.py now creates a default ALL-role/ALL-stage private routing desk as its fourth workspace stage, in human-routing, and includes it on the scriptless local HTML landing page. Changed HUMAN rounds require an independent NEW routing export. Missing/changed source material, reviewer self-reports and stage changes never constitute remediation, clearance, original consent or permission. No active assessments, scans, network interactions, targets or execution are performed.


## Direct guided terminal creation — no browser download required

A private interactive TTY can now compose the original lab endpoints directly into a 0600 local file and then build the entire offline private workroom. The source is admitted through the pinned original URL and LabScenario lab-only policy **before** private publication. Neither the wizard nor later workroom generation performs DNS, target I/O, subprocesses, scans or any active operation.

Create TWO distinct empty owner-only mode-0700 directories — one for original local source input, and one for the complete product workspace:

    mkdir -m 700 ~/private-lab-guided-input
    mkdir -m 700 ~/private-lab-guided-workspace
    python3 assessment-launchpad/workspace.py \
      --interactive-manifest \
      --input-dir ~/private-lab-guided-input \
      --workspace-dir ~/private-lab-guided-workspace

The CLI prompts for 1–16 literal HTTP(S) private isolated-lab URLs, with an empty line ending input. Text typed into the terminal is visible locally (do not paste credentials). The complete batch must pass exact pinned original lab gates. It then publishes lightup-lab-input-manifest.txt in the separate private source folder, followed by the entire original five-file preview bundle, HUMAN workroom, local editor, role routing inbox, source-bound guide and start screen.

No browser Downloads file or manual chmod is needed; all native writes use exclusive mode-0600 files. Empty input/output directories are required to prevent replacing old source or review work. Any error remains HOLD, with possible partial PRIVATE artifacts explicitly invalid for release; there is no silent cleanup that could remove previously existing user data. Use --verify-workspace-dir to reopen a complete source-bound packet without execution. Interactive mode cannot be used when verifying. Add `--explain-hold` to show the curated HOLD reason for workspace creation/reopen; raw filesystem exceptions, paths and endpoint values remain withheld, and the flag does not relax any admission gate.


## One-command HUMAN follow-up round — workroom, routing and delta

The independent next-round builder under assessment-launchpad/advance.py admits the same original private five-file Launchpad packet and a previous independently validated full PRIVATE HUMAN round. It then admits a **new** owner-private 0600 edited HUMAN worksheet, checks exact original source-bound slot/false-authorization schema, and packages the whole next step into a fresh separate mode-0700 root. No source-owner files, original HUMAN input or old output are modified.

Example: first complete offline workroom created by workspace.py at ~/private-lab-guided-workspace; after using its local browser editor, put the downloaded JSON in a NEW mode-0700 directory and chmod 600 it. Then:

    mkdir -m 700 ~/private-lab-next-round
    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --responses ~/private-import/lightup-lab-human-private.edited.json \
      --output-dir ~/private-lab-next-round

The workroom creates exclusive owner-only mode-0700 folders human-round (updated original-source-bound complete 0600 four-file HUMAN desk), human-editor (re-pinned private browser editor), human-routing (PRIVATE fixed-role/stage routing and counts), human-changes (PRIVATE scriptless HUMAN stage/role/note-change comparison and source-free counts), and PRIVATE 0600 START-HERE and OPEN-NEXT-ROUND local HTML navigation. It never changes original endpoint values, grants consent, starts assessment, contacts a target, executes commands or draws remediation conclusions.

Changed HUMAN count and chronological order refer only to the two explicitly supplied HUMAN files, not authenticated time. The current HUMAN stage is a non-authorizing self-report; no CLEARED/APPROVED stage exists.

Read-only reopening independently verifies the exact original Launchpad source packet, previous HUMAN round, all current source-bound HUMAN/role/delta/editor files, and the local landing/guide:

    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --verify-workroom-dir ~/private-lab-next-round

For another follow-up round, use the same original bundle and the new workroom's human-round as --previous-round-dir. The revised responses must always live in a separate owner-private source folder; choose a brand-new empty output root. A partial on-disk result after an error is not a validated workspace. All original security/privacy, authenticated consent and revocation, source-owner and mandatory CI, and HUMAN GO release gates remain entirely separate.


## Multi-round PRIVATE HUMAN history (2–8 original-source-bound rounds)

The separate offline history.py viewer accepts **2–8 already generated** HUMAN rounds in the human-selected order. Every previous round must be a complete owner-private four-file source-bound review packet for the exact same original private five-file Launchpad packet. This avoids conflating inconsistent original endpoints or copying HUMAN state between different source manifests.

    mkdir -m 700 ~/private-lab-human-history
    python3 assessment-launchpad/history.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-next-round/human-round \
      --output-dir ~/private-lab-human-history

Repeat --round-dir up to eight times in the operator-selected order. **The order is not authenticated time; it cannot prove that any reviewer acted at a particular date or that a finding was fixed.** No original source, HUMAN stage, reviewer identity, consent, scope or HUMAN GO is authenticated by this unsigned local tool.

Output in a distinct current-user-owned mode-0700 directory (all artifacts exclusive mode 0600):
- lightup-lab-human-history-private.html: single-file scriptless SHA-256-CSP-pinned PRIVATE HUMAN history. Collapsible endpoint-by-endpoint view of the original local URL, self-reported HUMAN stage, proposed role, private note and changes across 2–8 manually selected rounds. **Contains original endpoints and every selected private note. Do not host/share.**
- lightup-lab-human-history-routing-private.csv: PRIVATE latest-stage/role routing for each original ordinal, note length and number of changed HUMAN transitions. Never described as anonymous.
- lightup-lab-human-history-counts.json: counts only by fixed stage/role per round, adjacent transitions, changed HUMAN slots and note-presence counts. No URLs, hashes, paths, private note text or per-slot identifiers.
- lightup-lab-human-history-counts.csv: equivalent counts-only stage/role and transition matrix in static no-formula vocabulary.

The file integrity reopen is source-bound and read-only:

    python3 assessment-launchpad/history.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-next-round/human-round \
      --verify-history-dir ~/private-lab-human-history

The existing next-round builder assessment-launchpad/advance.py **now creates this 2-round HUMAN history automatically**, along with the current HUMAN desk/editor/routing/delta. To include more old rounds when advancing, add --earlier-round-dir for each earlier round, oldest first, up to **six earlier** rounds, then --previous-round-dir for the immediate prior round. The edited response worksheet becomes the final round (up to 8 total). The same --earlier-round-dir values in the same order must be provided to --verify-workroom-dir so it can reopen the original source, earlier HUMAN rounds, current HUMAN state and every new history artifact. The local HTML landing page includes a direct history link.

All work remains offline PRIVATE, LAB-ONLY DRAFT/HOLD. A HUMAN stage transition cannot mean CLEAR, APPROVE, consent, verified repair or end-user permission, and a missing source round is never evidence of a fixed vulnerability.


## Guided, no-intermediary HUMAN next-round creation

The next-round builder now also has a **PRIVATE TTY-only interactive mode**, reusing the existing admitted source-bound HUMAN editor in memory. This completes the native workflow without editing JSON manually or moving a browser download. It starts from a copy of the immediately prior original-source-bound HUMAN worksheet; earlier rounds and original packet stay unchanged.

    mkdir -m 700 ~/private-lab-interactive-next
    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --interactive \
      --output-dir ~/private-lab-interactive-next

For 3–8 rounds, provide up to six --earlier-round-dir values (oldest first) as documented above. The TTY menu displays **only original slot ordinals**, stages, neutral roles and note lengths; source endpoint values are not printed. Notes are entered without terminal echo through getpass. Blank stage/role/note inputs preserve the previous HUMAN value; entering a hyphen for a note clears it. An invalid entry or interruption aborts without publishing a new complete packet. The new workroom includes HUMAN updated notes, browser editor, private routing and 2–8 round chronological-*proposal* history, with all original source/rounds re-admitted immediately before publication. Its multi-round order is user-chosen, never authenticated chronology.

Interactive creation is mutually exclusive with --responses and with read-only --verify-workroom-dir. No browser, external service, model, scan, target operation, authorization, consent or HUMAN GO is involved. The resulting HTML/JSON includes sensitive PRIVATE notes and endpoint URLs, remains unencrypted local 0600 and must not be shared or hosted.


### Navigable 2–8-round attention and bounded source custody

The full PRIVATE history now starts with a HUMAN-only per-round workload matrix (NEEDS_INPUT, HUMAN_REVIEW, FOLLOW_UP, note-presence counts) and a current HUMAN attention queue. The queue lists only fixed HUMAN states, fixed reviewer roles, note lengths and original slot ordinals, with local anchor links to each expandable private endpoint-by-endpoint discussion. There are **no inferred security severities, remediation findings, real deadlines or approval flags**.

The native output enforces a consistent 512-KiB ceiling for each saved history item, including a full eight-round, sixteen-slot discussion whose private HUMAN notes may contain HTML-escaped characters. The standalone history reopener and integrated next-round reopener use the same bound, reject missing/extra artifacts, require owner-only mode 0600 regular files and re-admit original source and all selected previous HUMAN rounds. If a legitimate input exceeds that fixed product bound, generation refuses publication rather than issuing a saved packet it cannot later reopen.

No QA suites, scans, real target or model actions are required or performed. The user-selected sequence is NOT authenticated time and changed HUMAN notes are not evidence that work was performed or a vulnerability fixed.


## Compare any manually selected HUMAN interval, including return-to-prior status

The 2–8-round private history supports an explicit operator-selected interval. This is useful when HUMAN planning passed through intermediate revisions and the latest state alone hides temporary stage/role changes. For example, with four rounds in an already established PRIVATE history input order:

    python3 assessment-launchpad/history.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-round-02/human-round \
      --round-dir ~/private-lab-round-03/human-round \
      --round-dir ~/private-lab-round-04/human-round \
      --compare-from-round 1 \
      --compare-to-round 4 \
      --output-dir ~/private-history-interval-01-to-04

Any two different original round ordinals within 1..N are allowed as long as from < to. By default the first and last rounds are compared. The PRIVATE scriptless HTML shows an ordinal-level net stage/role change, note-change indicator and separate markers for a HUMAN stage or reviewer role that returned to its original value after differing in one of the manually inserted rounds. The source-free counts JSON/CSV include the total net changed slots, HUMAN stage/role/note changes and stage/role returns, but no original endpoint, source path/hash or note text. The ordinary next-round workroom uses the default first-to-latest HUMAN interval and includes the comparison automatically.

This is **not** a status change on an actual system, not verified remediation or regression, not authenticated real-world chronology, not identity attestation, not consent and not release. A HUMAN status returning to its previous value has no security meaning by itself. To reopen the custom interval artifact, use --verify-history-dir instead of --output-dir with the SAME repeated --round-dir list and the SAME --compare-from-round/--compare-to-round values.


## Updated PRIVATE HUMAN management briefing and canonical packet integrity

A HUMAN history now generates a **fifth** self-contained artifact: lightup-lab-human-history-brief.html. It is a scriptless, CSP-hash-pinned offline management briefing that displays stage counts for every manually selected 2–8 HUMAN rounds, adjacent HUMAN change totals, currently proposed reviewer-role allocation, and net plus return-to-earlier-value counts for the requested interval. It contains no original endpoint URLs, per-slot ordinals, source paths/digests or private note text. It is **PRIVATE by default** because even aggregate counts from a small lab engagement can reveal context; it is not an anonymity or client-consent guarantee.

The existing one-command next-round workroom automatically includes the source-free briefing and links to it from OPEN-NEXT-ROUND-PRIVATE.html. The original detailed PRIVATE history is still available separately, under a distinct link, and must never be served or shared. The standalone history's exact read-only reopen now expects five canonical files; both standalone and integrated publication share their previous source/round re-admission, 512-KiB history-item capacity and exclusive owner-only mode 0600 output.

### Strengthened original-source reopen and private source isolation

- launchpad.py now refuses any missing or unexpected file in its original five-file private bundle. It reconstructs the original scriptless CSP-pinned HTML from the pinned renderer and validated canonical manifest, receipt fields and exact display-only --preview-only command. A matching hash in a **rewritten unsigned receipt** is no longer sufficient to re-open arbitrary replacement HTML. This remains unsigned byte consistency, not cryptographic source authentication.
- workspace.py demands the complete canonical file inventory in each private HUMAN review/editor/routing subfolder in addition to its original Launchpad and parent-inventory checks.
- review_desk.py refuses nonempty destination directories, requires existing response worksheets to be in distinct private source directories, and demands exact four-file inventory on read-only reopen.
- compare_review.py and its shared original-source human-round reader require exact private file inventories. Standalone routing.py and editor.py now likewise demand empty new output roots and exact inventories on reopen.
- advance.py checks the full bounded output sizes, including all history artifacts, **before creating** its new private subdirectories. Its integrated stored packet cannot be published in a state which would later exceed the read-only re-open limits.

No changes grant scope, consent, risk approval, authorization, release, scanning or real security assessment. The original release gates, independent source ownership and separate action-time revocation checks remain mandatory. No QA or regression suites were written or run.


## Voluntary PRIVATE HUMAN reviewer handoff — selected role, stage and original slots

The new independent native assessment-launchpad/role_handoff.py creates a small original-source-bound PRIVATE offline reviewer dossier from 2–8 existing complete HUMAN rounds. It is a privacy-minimized alternative to sharing the complete multi-round PRIVATE history, which contains every endpoint and every HUMAN note.

Choose one latest self-reported HUMAN reviewer role, optionally one latest self-reported HUMAN stage and optionally exact original slot ordinals:

    mkdir -m 700 ~/private-lab-role-subset
    python3 assessment-launchpad/role_handoff.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-next-round/human-round \
      --role SECURITY_REVIEWER \
      --stage FOLLOW_UP \
      --slot 2 --slot 5 \
      --output-dir ~/private-lab-role-subset

A supplied --slot must match the selected role and stage in the latest round. Duplicate, missing, incompatible and out-of-range ordinals are rejected rather than silently broadening disclosure. Without --slot, all matching latest HUMAN slots are included. Zero matching HUMAN slots is a non-authorizing HOLD, not grounds to invent or infer approval.

The four resulting exclusive 0600 private files (in a NEW empty 0700 owner-only folder):
- lightup-lab-role-handoff-private.html: standalone scriptless CSP-hash-pinned PRIVATE printable dossier. Contains only selected original endpoint URL values and HUMAN stages/roles/private notes belonging to the chosen suggested role across the rounds. Historical notes belonging to other suggested roles are withheld even when the endpoint is selected. Do not host or share publicly.
- lightup-lab-role-handoff-private.csv: PRIVATE selected original slot ordinals and latest fixed vocabulary and lengths, omitting endpoint values and note texts. Per-slot ordinals can still be sensitive.
- lightup-lab-role-handoff-counts.json: separate low-detail aggregate counts. No original URLs, per-slot ordinals, source paths/digests, or HUMAN note text. Tiny cohorts can still be identifiable; keep private.
- START-HERE-ROLE-PRIVATE.txt: safe-use operator guide with explicit non-authorizing HUMAN-only limitations.

To read-only reopen the full source-bound packet, supply the SAME ordered --round-dir values, role/stage/slot selection and original --bundle-dir, replacing --output-dir with --verify-handoff-dir. The original five-file source and all complete previous HUMAN rounds are re-admitted before publishing. The output is capacity-bounded to 512 KiB per artifact, owner-only, no overwrite, and requires exactly the original four output files.

The existing native advance.py next-round builder can include a selected role handoff as part of its full new private workroom in one command:

    mkdir -m 700 ~/private-next-with-role
    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --responses ~/private-import/lightup-lab-human-private.edited.json \
      --handoff-role SECURITY_REVIEWER \
      --handoff-stage FOLLOW_UP \
      --handoff-slot 2 --handoff-slot 5 \
      --output-dir ~/private-next-with-role

The resulting human-selected-role folder contains the four private files and the scriptless local OPEN-NEXT-ROUND-PRIVATE.html navigation now links the dossier. Without --handoff-role no dossier is created. A subsequent --verify-workroom-dir must be run with identical --handoff-role, --handoff-stage and any --handoff-slot values; otherwise the complete-workroom admission fails.

IMPORTANT: Human roles are unsigned self-reports, not verified identities or server-side access control. A privacy-reduced file is not automatically safe to distribute: an operator must authenticate and authorize recipients separately. This product does not issue consent, grants, assessment scope, clearance, completed findings, remediation, real chronology, security permissions or HUMAN GO. No active target, model or scan actions occur. Existing source-owner, CI/permanent VPS, independent security/privacy, actual client/operator consent and action-time revocation/HUMAN GO release gates remain mandatory.


## Returning role-filtered HUMAN replies

See [ROLE_RETURN_GUIDE.md](ROLE_RETURN_GUIDE.md) for the complete offline role-specific CSV or non-echoing terminal reply -> source-bound owner-only HUMAN worksheet -> native advance workflow. Voluntary roles are not authenticated, and no scope/consent/target action occurs.


Owner-only multi-recipient workflow: advance.py accepts up to five repeatable --role-return-dir inputs from disjoint selected HUMAN roles. See ROLE_RETURN_GUIDE.md for original round ordering, overlap refusal, private receipts, the browser editor and source-bound import. This is never consent or authorization.


## PRIVATE HUMAN return reconciliation desk

Native offline per-role/ordinal change desk and source-free aggregate workload across 1–5 disjoint original role replies: [ROLE_RECONCILIATION_GUIDE.md](ROLE_RECONCILIATION_GUIDE.md). Separate exact source-bound CLI role_return_reconcile.py, scriptless CSP-pinned HTML, private CSV, aggregate JSON, deterministic owner-only read-only reopen. This is NOT recipient authentication or a grant.


## Manual resolution of overlapping HUMAN role returns

If two original private selected-role returns claim the same local slot, advance.py deliberately HOLDS. Use [ROLE_CONFLICT_GUIDE.md](ROLE_CONFLICT_GUIDE.md) and role_return_conflicts.py to prepare a PRIVATE role/slot choice CSV + scriptless CSP offline HTML, explicitly choose a source packet per conflict, and produce a complete owner-private canonical HUMAN worksheet for advance.py --responses. This is never automatic precedence, identity proof, remediation validation, consent or an assessment permission.


## Direct owner PRIVATE manual conflict handoff to next HUMAN round

The original resolved four-file overlap packet plus original chosen CSV and original source-bound role returns can now be imported with advance.py --conflict-resolved-dir, --conflict-decision-file and repeated --conflict-return-dir. Preserves a scriptless local provenance desk inside human-manual-conflict-review without duplicating the complete PRIVATE notes worksheet. See [ROLE_NATIVE_MANUAL_INTAKE.md](ROLE_NATIVE_MANUAL_INTAKE.md). No assessment authorization, real identity or scan.


## Offline HUMAN action desk

Source-bound multi-role reconciliation now includes an operator-only, locally filterable and printable HTML next-action desk plus fixed-vocabulary CSV for every original slot, prioritizing missing replies without treating HUMAN_REVIEW as approval. The PRIVATE next-round home links directly to this view. See [ROLE_RECONCILIATION_GUIDE.md](ROLE_RECONCILIATION_GUIDE.md). No network, grants or scans.


### PRIVATE HUMAN action desk: safe selected-row handoff

For a role-return reconciliation packet (or the next-round workroom that
embeds it), open `lightup-lab-human-next-actions-private.html` locally.
Select a voluntary role, original reply status, suggested next action,
self-reported HUMAN stage and/or PRIVATE note-change flag. Clear all HUMAN
filters restores the complete local view without altering source data.
The live counts update for the chosen view. Tick individual original slots,
then use **Select displayed slots** to add all rows currently visible without
clearing earlier selections; selections survive filter changes in memory only.
**Deselect displayed slots** removes only the visible rows from the queue; **Clear all selections** resets the queue. Open **Review selected rows before CSV download** to inspect the exact selected source ordinals and fixed HUMAN labels, including rows hidden by filters; that preview is never printed. **Print only displayed PRIVATE rows**
prints the current filtered view. **Download all selected PRIVATE rows**
exports the entire explicitly checked fixed-enum/ordinal queue, including
hidden rows; **Download selected-and-visible PRIVATE rows** exports only the
intersection of checked rows and currently displayed filters, useful for
preparing a minimal single-role handoff. Both files preserve original source
order, fixed schema and no endpoint/note text. The renderer refuses out-of-order
original slot lists. The browser does not
persist selections. To resume a previously saved selection, use **Reopen earlier
PRIVATE selected HUMAN CSV** in the same offline action desk. The file is read
locally (max 8192 bytes), strictly decoded as canonical UTF-8/CRLF and matched
row-by-row, including every enum and source order, against the *current exact*
original worklist. Altered source details, duplicate slots, unknown columns,
noncanonical encodings or foreign selection documents HOLD without modifying
the current selection. The staged preview shows **imported-only, current-only
and shared original slot ordinals**; only an explicit **Add imported selection**
or **Replace current selection** changes the in-memory queue. The separate
**Download PRIVATE selection differences CSV** button locally exports the
current-versus-imported source-ordered original slot membership difference:
`NEWLY_SELECTED`, `NO_LONGER_SELECTED`, or `UNCHANGED_SELECTION` plus fixed HUMAN
role/status/action fields. It is a **PRIVATE unsigned ordinal-only comparison**,
not an original selected-action CSV; it must not be passed as input to the
native `action_handoff.py` or as proof of a real completed review. Importing a
selection neither authenticates its source nor changes the original worklist
and source/returns, does not write browser storage, and never sends data.
Neither print nor CSV contains endpoint URLs or human notes, but role/slot
combinations may identify people; keep printouts and CSV private.
No reviewer is authenticated, no recipient sharing is performed, and no
consent, scan, grant or HUMAN GO is inferred.

### Original-source re-admission for selected HUMAN action CSV

Do **not** mistake the browser-selected CSV for an authenticated reviewer
reply. `action_handoff.py` optionally converts this private browser selection
into a fresh, four-file original-source-bound PRIVATE native handoff after
checking all selected rows and order against the exact original five-file
Launchpad bundle, original operator-ordered HUMAN rounds and original selected
role-return packets. No new grants, targets, scans or reviewer identities.
See `ROLE_RECONCILIATION_GUIDE.md` for the complete create/reopen commands.
Run `action_handoff.py` with `--preview-only` first to re-admit the complete
original source set and selected CSV, display selected/original slot counts plus fixed-vocabulary counts across the
five HUMAN dimensions, and exit before opening or creating any output directory. The downloaded
browser CSV must first be moved into a private `0700` folder
and set to mode `0600`. Its six-column header must remain exactly
`original_slot,latest_suggested_role,private_human_reply_status,latest_self_reported_human_stage,suggested_operator_next_step,private_note_changed`;
rows must be an ordered, unique subset of the freshly reconstructed original
worklist. The native handoff optionally accepts `--suggested-role SECURITY_REVIEWER`
(or another original fixed role) to emit only matching selected rows after
first admitting the **complete** original source and selected CSV. It fails
closed if the filtered queue is empty. The fixed role is a HUMAN proposal, not
a verified recipient; the owner must still authenticate any recipient.
The native summary reports counts by all five HUMAN dimensions
(role, reply status, self-reported stage, next action and note-change flag),
not note content. With `--suggested-role`, preview/HTML/JSON distinguish the
selected rows for that proposed role, the full all-role selection, rows omitted
because they belong to other roles, and slots truly unselected across all roles.
All outputs remain private mode `0600`; missing or modified
original source bytes keep the workflow in HOLD.

### Two PRIVATE selected-action CSVs → original-source-bound change dossier

`action_selection_compare.py` adds a complete offline **HUMAN selection
membership** workflow: compare two separately downloaded PRIVATE selected
CSV snapshots against the *same* freshly re-admitted original Launchpad source,
2–8 manually ordered HUMAN rounds and 1–5 role returns. Both six-field CSVs
must be an exact, unique, original-order subset of the original worklist.
It classifies original local slots as newly selected, no longer selected or
selected in both. Optional `--suggested-role SECURITY_REVIEWER` (or another
fixed role) narrows output to that original proposed HUMAN role, **after** both
complete selections and all source packets are admitted; the operator still
must authenticate recipients. Role-only output separates filtered before/after
counts from all-role totals. Default output is unchanged. The browser action desk
also offers a selected-role-only difference CSV when one role is selected and a
prior selection is loaded; the preview shows role-only current/imported counts
and ordinal changes before export. Creates an owner-only four-file packet (scriptless
network-denied CSP HTML, source-minimal CSV, fixed-vocabulary counts JSON and
handling guide). Breakdown by suggested HUMAN role/next action is also
included. Use `--preview-only` for write-free counts or `--verify-output-dir`
for read-only reopen. No target URLs, source digests, notes or reviewer
identities are exported. Even private ordinals and role combinations may be
identifying. **Manual selection order does not prove event chronology;
removed selection is not a remediated finding.** Full create/reopen commands:
[ACTION_SELECTION_COMPARISON_GUIDE.md](ACTION_SELECTION_COMPARISON_GUIDE.md).


## Two-source private slot map — explicit source-to-result traceability

The native `combine_manifest.py` already publishes a source board and
source-local → combined-slot CSV for multi-source combinations and any
combination that omits sources. For a **simple two-source combination**,
`--source-slot-map` now opts into the same four-file PRIVATE receipt:
the canonical manifest, unsigned source receipt, scriptless source board,
and per-source ordinal/slot CSV. This is useful when the operator needs to
review exactly which local slots from each input occupy the resulting
manifest without exposing literal endpoint values in the map.

```bash
mkdir -m 700 /private/combined-manifest-with-map
python3 assessment-launchpad/combine_manifest.py \
  --first-manifest /private/source-a/manifest.txt \
  --second-manifest /private/source-b/manifest.txt \
  --mode append \
  --source-slot-map \
  --output-dir /private/combined-manifest-with-map
```

Open `lightup-manifest-source-board-private.html` for the source-level
retained/discarded view; it links directly to `lightup-manifest-source-slots-private.csv`.
The CSV lists every source-local slot, its resulting slot (blank when discarded),
fixed-vocabulary selection state and `REVIEW_ONLY` label. The CSV and HTML
contain no endpoint values, source filenames, paths, free text or source
hashes. The unsigned private JSON receipt remains sensitive and is not an
attestation of provenance, consent, client identity, lab isolation or
authorization.

For an exact **read-only** reopen, repeat the same original manifest order,
mode, `--source-slot-map` flag and output directory, and add
`--verify-output`:

```bash
python3 assessment-launchpad/combine_manifest.py \
  --first-manifest /private/source-a/manifest.txt \
  --second-manifest /private/source-b/manifest.txt \
  --mode append \
  --source-slot-map \
  --output-dir /private/combined-manifest-with-map \
  --verify-output
```

A write-free `--dry-run --source-slot-map` also prints the same bounded
source-local → result-slot CSV to stdout after full native source admission,
so operators can review retained/discarded ordinal mapping before selecting
a publication directory. Multi-source and omission previews already include
this ordinal-only mapping; the dry-run creates no files.

The explicit flag participates in the exact output shape: omitting it on
reopen will HOLD if the original bundle contains the map, and adding it
will HOLD if the original bundle was published in the legacy two-file
shape. Existing v1 two-source receipts and historical multi-source receipts
remain supported by their original exact-shape reopen/admission paths; this
option does not rewrite them. For 3–8 source files or explicit source
omissions, the board and slot map are already included and the option is
redundant. This is offline planning only; the original source-owner,
exact-head hosted and permanent named-VPS CI, independent security/privacy
review, authentic distinct current client/operator consent with action-time
revocation, #177/#182/#829 and explicit HUMAN GO gates remain mandatory.


### Saved manifest receipt byte-canonical admission

The PRIVATE manifest change desk now reserializes each admitted saved
combine receipt with the native sorted-key, compact JSON encoding and one
final LF, and requires byte-for-byte equality before it trusts the receipt
for local bundle consistency. A receipt with altered whitespace, key order,
or noncanonical JSON representation now remains in HOLD rather than being
accepted merely because it parses. Historical native receipts generated by
the same canonical writer remain readable. This protects exact local
reproducibility only; the receipt remains unsigned and does not authenticate
source ownership, chronology, endpoints, consent, scope approval or HUMAN GO.


### Portable PRIVATE manifest-change CSV

The native `manifest_change_desk.py` now publishes a third artifact,
`lightup-private-manifest-delta.csv`, with the fixed columns
`change_state,before_slot,after_slot,review_state`. Its rows contain only
`UNCHANGED`, `MOVED`, `REMOVED` or `ADDED`, original integer slot
ordinals and `REVIEW_ONLY`; removed slot values are blank. No endpoint
URLs, source paths, source hashes, notes or free text are present in the CSV.
The scriptless HTML comparison page links directly to this CSV and to a self-contained
copy of `manifest_change_review.html` for a local HUMAN follow-up workflow. It is a
portable **PRIVATE** planning ledger, not a vulnerability report, proof of chronology,
or evidence that removal fixed a finding.

New change-desk publications contain four exclusive mode-0600 artifacts inside the
owner-owned mode-0700 output directory: source-bound JSON, scriptless HTML, ordinal-only
CSV and the exact CSP-pinned offline HUMAN follow-up editor. The generated HTML opens
the editor locally; import the adjacent CSV, assign fixed follow-up stages, and export
the full ledger. The editor can re-import its own five-column export to resume stages.
All HUMAN stages remain separate from the unchanged `REVIEW_ONLY` source status.

Exact reopen admits the complete four-file shape byte-for-byte. For compatibility,
older canonical native three-file JSON+HTML+CSV bundles and two-file JSON+HTML bundles
remain read-only reopenable using their original scriptless HTML shape; they are not
rewritten to add the editor. The editor is copied only into newly published bundles.


The change desk re-admits both original saved manifest bundles again at
the output boundary, immediately before exact reopen or publication. If
either canonical manifest's original bytes/slot list changed while the
comparison was being prepared, it holds instead of publishing a stale delta.
This is a local source-drift guard only; it does not make unsigned local
receipts authentic or establish when an operator selected either snapshot.


### Browser HUMAN follow-up editor for manifest-change CSV

Open `assessment-launchpad/manifest_change_review.html` directly in a browser (no server required), or use the self-contained copy included in a newly generated change-desk output directory. Select the adjacent `lightup-private-manifest-delta.csv` produced by `manifest_change_desk.py`. The page validates the fixed native CSV header, REVIEW_ONLY source marker, bounded slot ordinals, row count and allowed transition shapes, then lets a human assign one fixed follow-up stage per ordinal row:

- `NOT_REVIEWED`
- `REVIEWED`
- `FOLLOW_UP`
- `NOT_APPLICABLE`

Use **Export full HUMAN follow-up CSV** to save the complete ledger. Filters affect only the visible table, never which rows are exported. You can re-import that five-column CSV later to resume the saved fixed-vocabulary stages; importing a fresh native four-column delta starts every row at `NOT_REVIEWED`. The original `review_state=REVIEW_ONLY` remains unchanged; `human_follow_up` is a separate local workflow field. The browser tool does not include endpoint URLs, source paths, source hashes or free-text notes, and keeps edits in memory only. Its restrictive CSP hashes the exact inline script and stylesheet; no external assets, storage, network, telemetry or target activity are used.

This is a convenience format check and HUMAN follow-up worksheet, **not** source authentication, evidence of remediation, authorization, consent, revocation status or HUMAN GO. Keep the downloaded CSV private. The original native CLI remains the source-bundle admission boundary.
