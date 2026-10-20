# LightUp — current PRIVATE scope offline distribution (DRAFT/HOLD)

## What this delivers

This is an **add-only**, isolated distribution companion for the existing [integrated scope workspace, PR #1680](https://github.com/Zennay/Lightup/pull/1680). The original owner source and the eight independent original workrooms are not edited. This branch is pinned to **source HEAD `0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc`** and deliberately does not claim ownership of that PR.

The source owner built an offline ZIP at an earlier HEAD `2cfd29d`. The subsequent real large-source acceptance and cursor parser improvements `28f30e8` + `0f76f2f` were not yet included in that original published ZIP. This isolated builder recreates the offline distribution from the **current** pinned source in a disposable workspace and publishes the finished archive and standalone UI **only into `scope-current-bundle/`**.

## Build the actual portable product

From a clean checkout of this branch with Python 3.11+:

```sh
python3 scope-current-bundle/build.py
```

This is a **product build**, not a QA suite, scanner, tool authorization, remote request or deployment. It uses only Python's standard library and invokes the existing original package builder against a temporary copy. It does not edit the eight original source owners or tracked original generated files.

After successful build:

- `LightUp-Scope-Offline-DRAFT-HOLD.zip` — **complete portable package**, 8 originally pinned apps + interactive HUMAN source workroom.
- `index.html` — offline launcher.
- `handoff.html` — source-fingerprint-aware PRIVATE HUMAN assignment, exact continuity reopen and source-drift comparison.
- `verify.html` — local archive byte-hash reader.
- `SOURCE-MANIFEST.json` — byte inventory from original packager.
- `DIST-MANIFEST.json` — extra reproducible source pin and distribution SHA-256 inventory.

Open the downloaded ZIP **locally**. No web hosting, external API, account, or target is required. Original encrypted companion packets remain opaque; the workroom does not decrypt them. For actual privately identifying materials, use locally authorized private storage and trusted recipients.

## Original-source revision brief — HUMAN follow-up product

The second offline product `change_brief.py` accepts two actual original `SOURCE-MANIFEST.json` files (an earlier separately exported package and the newer package). It rejects ambiguous duplicate JSON keys, malformed or oversized records, unexpected authorization flags, unsafe paths, and duplicate file entries. The result is an **owner-only scriptless HTML decision brief** (`index.html`) with added / changed / unchanged / absent *original package files*, original unsigned byte fingerprints and original companion source HEAD drift. It also emits a separately **source-minimized category-counts JSON** without file names, hashes, or targets.

**New PRIVATE interactive HUMAN desk:** `workroom.html` is an actual standalone offline browser application containing a source-bound row for each original file, filters for source status/HUMAN stage, local team and notes editors, full-batch RFC4180 CSV import of existing original HUMAN review and explicit confidential CSV download. A **CSP SHA-256 fingerprint pins the exact embedded offline script and stylesheet**, no network/storage/cookies. It rejects an imported worksheet if even one original filename, SHA, source revision, row order, change category, stage or HUMAN value is ambiguous or invalid. Failed import leaves the entire in-memory desk untouched. The passive `index.html` and separate source-minimized source counts remain independent. Small cohorts and low-frequency categories are redacted rather than falsely advertised as anonymous.

```sh
python3 scope-current-bundle/change_brief.py \
  PREVIOUS/SOURCE-MANIFEST.json \
  CURRENT/SOURCE-MANIFEST.json \
  NEW-PRIVATE-REVIEW-DIRECTORY
```

The destination directory must **not exist**; the tool creates a private 0700 folder and exclusive 0600 outputs. Open `workroom.html` locally to edit and explicitly download the same source-bound worksheet that the original CLI exports, or use the private CSV directly with your local editor. It does not scan, approve, reconcile actual client data, claim a removed source is fixed, or reinterpret source hashes as authentic provenance. Human owners explicitly review changes and must still obtain real fresh permissions independently.

## Edit and return the actual HUMAN review

`change_brief.py` also creates `human-review-template.csv` containing the **exact** original old/current SHA-256, source path, change class and old/new file digests for each original package file. A reviewer may fill **only** `human_stage` (`unreviewed`, `investigating`, `escalated`, `documented`; never a verified/fixed state), `human_team`, and `human_notes`. This is PRIVATE source-sensitive material, not anonymous.

After edits, the separate independent handoff CLI strictly admits the **same two original manifest bytes** and the filled CSV. The entire worksheet must retain identical file list, original hashes, row count, ordering, change classes and supported HUMAN stages. Any source drift or malformed return rejects the whole import without partial status promotion.

```sh
python3 scope-current-bundle/human_followup.py \
  PREVIOUS/SOURCE-MANIFEST.json \
  CURRENT/SOURCE-MANIFEST.json \
  REVIEW/human-review-template.csv \
  NEW-PRIVATE-HUMAN-OUTPUT-DIRECTORY
```

Output is a fresh owner-only directory containing a **scriptless printable private HUMAN follow-up report** (`human-review.html`) and separate **source-minimized HUMAN stage/source change counts** (`source-minimized-counts.json`) with no paths, hashes, team names or freeform notes. No form executes a scan or changes original grants.

## PRIVATE multi-revision HUMAN attention and progress history

For the **same two original source manifests**, the operator may preserve earlier and latest separately downloaded *complete* HUMAN CSV assignments and compare purely HUMAN decisions. The new `review_history.py` requires both originals, both source-byte-bound complete worksheets and a NEW private directory:

```sh
python3 scope-current-bundle/review_history.py \
  PREVIOUS/SOURCE-MANIFEST.json \
  CURRENT/SOURCE-MANIFEST.json \
  PRIVATE/earlier-human.csv \
  PRIVATE/latest-human.csv \
  NEW-PRIVATE-HISTORY-DIRECTORY
```

It produces a scriptless PRIVATE HTML comparison of human review stage/team/notes changes, plus a prioritised **HUMAN attention** table for any latest human stage not documented OR any original source file that changed, was added or is absent from local selection. A separate file contains only unsigned stage-transition and attention counts; original paths, human team names, source hashes and notes stay in the PRIVATE report. The same source-byte identity and row order is rechecked separately for **both** human worksheets before any output. No stage can become `fixed`, `authorized`, `revoked`, or a verified security verdict.

## Least-disclosure multi-team HUMAN recipient exchange

Use this when reviewers should **not** receive every original file name, SHA-256 fingerprint, private source record or all other reviewers' HUMAN notes.

Prepare PRIVATE per-team replies from the exact two **original** `SOURCE-MANIFEST.json` bytes and a fully re-admitted source-exact HUMAN worksheet. The worksheet's `human_team` values select recipient groups; assigned HUMAN team names reuse the original source-bound worksheet values (1–80 characters, without control characters, spreadsheet formulas or surrounding whitespace), up to 16 groups; these are **not authenticated identities**. The recipient files are numbered safely by group slot rather than by team name. Leave `human_team` empty for records intentionally not routed.

```sh
python3 scope-current-bundle/recipient_exchange.py prepare \
  PREVIOUS/SOURCE-MANIFEST.json \
  CURRENT/SOURCE-MANIFEST.json \
  PRIVATE/current-human.csv \
  NEW-PRIVATE-RECIPIENT-PACKET-DIR
```

This creates **private 0700 directory / 0600 files** with one confidential, source-minimized `recipient-XX.html` **offline browser editor** per team and an optional exact-row `recipient-XX.csv` template. Each team receives only its own local ordinal slots, declared source-change class, prior HUMAN stage and proposed HUMAN stage/note fields. No original source paths/hashes, source-owner private notes or other teams' assignments are included in the recipient outputs. The HTML has **CSP SHA-256 pinned embedded JavaScript and CSS**, no external requests/storage and explicit editable HUMAN replies with atomic source-row-bound CSV restore/export.

**Do not distribute** `PRIVATE-owner-receipt.json`, other teams' files or the original source and HUMAN CSV. Privately deliver exactly the intended recipient's own `recipient-XX.html`, and receive its edited `LightUp-PRIVATE-HUMAN-recipient-XX.csv`. The session/row tokens are **not cryptographic actor authentication or client consent**; a trusted distribution channel and independently authenticated participants remain the owner's responsibility.

Reconcile from the exact original bytes, the PRIVATE owner receipt and one to sixteen complete recipient responses. Missing teams are recorded as awaiting rather than interpreted as a review PASS. Every supplied team response is checked atomically for original session, team slot, row ordinals, random source-minimized row references, ordering and unmodified original HUMAN status; proposed fields remain **unverified HUMAN self-reports**.

```sh
python3 scope-current-bundle/recipient_exchange.py reconcile \
  PREVIOUS/SOURCE-MANIFEST.json \
  CURRENT/SOURCE-MANIFEST.json \
  PRIVATE/current-human.csv \
  PRIVATE/PRIVATE-owner-receipt.json \
  NEW-PRIVATE-TRIAGE-DIR \
  PRIVATE/reply-team-1.csv [PRIVATE/reply-team-2.csv ...]
```

Output now includes **two complete PRIVATE source-owner interfaces**: `PRIVATE-HUMAN-proposals.html` is scriptless source-rich triage; `PRIVATE-HUMAN-owner-decisions.html` is a **CSP SHA-256 pinned standalone interactive original-owner workroom**. The owner can filter all original source rows or only replies, inspect source-rich proposed stage/PRIVATE note, independently **retain or explicitly adopt** each recipient's *HUMAN stage only*, edit their own original PRIVATE notes and export a new complete original-manifest-byte-bound `LightUp-PRIVATE-owner-selected-HUMAN-draft.csv`. The recipient note is shown for review but **not silently copied into** the original HUMAN notes; existing original source bytes and permission fields remain untouched. No automatic acceptance on import.

The CLI also produces the PRIVATE original-path-specific response CSV and an independent **source-minimized count report**; counts can still reveal membership in small cohorts and must not be called formally anonymous. **Nothing is auto-accepted into the original HUMAN worksheet**, original review history, domain/grants, target state, real recipient identity, actual consent or revocation. The owner must explicitly export the new HUMAN draft (and may subsequently use the unchanged `human_followup.py` or `review_history.py` workflows). The owner stage decision is not a LightUp authorization or security clearance.

## Portable encrypted PRIVATE handoff — no original identity disclosure

`recipient_exchange.py prepare` now also writes a complete local **`PRIVATE-encrypted-courier.html`** beside the PRIVATE owner receipt and numbered reviewer workrooms. The new `private_courier.py` composes a single-file standalone browser app from `private_courier.js`, with exact CSP SHA-256 pinned stylesheet and script and no external libraries, network calls, cookies or browser storage.

**Ready-to-open courier:** [PRIVATE encrypted offline courier HTML](PRIVATE-encrypted-courier.html) is **actually committed and directly downloadable** in this PR. It is a standalone local file generated from the pinned source and CSP-hash-bound offline script/style, containing NO customer data. This is separate from the still-unpublished rebuilt eight-apps ZIP. `recipient_exchange.py prepare` also generates the same courier into each fresh PRIVATE recipient handoff directory.

**Source-owner flow:** open `PRIVATE-encrypted-courier.html` locally; select **only the intended team's** `recipient-XX.html` (or optionally their `recipient-XX.csv`), enter and confirm a unique strong passphrase, and explicitly export `LightUp-PRIVATE-HUMAN-handoff.luhr`. Deliver only that encrypted file over an approved route; give the passphrase to the independently authenticated intended recipient through a separate trusted channel. The recipient opens the identical offline courier locally, selects the `.luhr` packet, supplies that passphrase and manually downloads the original offline HTML/CSV. A reviewer may reply privately as before and optionally encrypt the reply with a different passphrase for the verified source owner. **Never include** `PRIVATE-owner-receipt.json`, source-rich original files or other teams' responses in a recipient transfer.

**Actual data format and guarantees:** one bounded UTF-8-safe `.html`/`.csv`/`.json` file or the complete original pinned offline `.zip` package (max 2 MiB); fixed unambiguous 40-byte binary header with version magic, fresh 16-byte salt, fresh 12-byte nonce and plaintext byte count; PBKDF2-SHA-256 310,000 iterations to derive an AES-256-GCM key, with the complete envelope header authenticated as additional data and a 128-bit authentication tag. Decryption checks the exact length, magic, encrypted filename and byte budget, and **does not automatically open or execute recovered files**. Invalid ciphertext/password causes HOLD and leaves originals unchanged. New encrypted files use fresh random salt and nonce on every export. There is no reversible recovery if the password is lost.

**Optional independent byte handoff:** after encryption, the courier displays the ciphertext SHA-256 hash so the original sender may provide that fingerprint through a separately authenticated channel. Before decryption the recipient may enter that exact 64-character SHA-256 digest; a mismatch aborts decryption **before opening the encrypted AES-GCM payload**. A matching digest is only a consistency check for the same ciphertext, NEVER authenticates a sender or client/operator permission. The courier also clears some temporary in-memory plaintext buffers after encryption/decryption, but **cannot guarantee all copies disappear from browser memory**.

**Threat boundaries:** the courier encrypts sensitive local transport, but a password or a successfully opened envelope is **not** independent authentication of the original source, recipient, client, tenant, operator, grant, consent, revocation, approved request or security finding. A malicious correspondent with the shared password could create a plausible envelope. WebCrypto must be available in a secure browser context (modern local `file://` usually qualifies); unsupported browsers fail closed. HTML from unknown correspondents may still be unsafe if a human manually opens it after decryption. The original mandatory security and release reviews remain unchanged. Generated HTML/ZIP files are **source deliverables only until built**; do not claim binaries already published by this PR.

## Fail-closed build and immutability

`build.py` checks **all 14 original offline builder source byte digests** of the original packager, HUMAN handoff and JSON inspector, copies eight original app directories without symlinks, reruns original **60-file pinned source verification**, validates the original DRAFT/HOLD manifest and its six literal false authority flags, and checks every output destination for collisions before writing. Output uses no-follow exclusive create, 0600 file mode, and fsync. If existing distributed files differ, the build **refuses replacement**; publish a newly named revision after legitimate source review instead.

SHA-256 here is **only byte matching**, never authenticated operator/client identity, signed producer authenticity, fresh consent, tenant permission or scanner authorization. The generated distribution is a local review tool with PRIVATE source-sensitive content.

### Privacy of numerical handoffs

The category exports are **source-minimized, not guaranteed anonymous**. The shared `privacy_counts.py` suppresses all category figures for cohorts below five original rows and suppresses 1–2 observations in larger cohorts. Private HTML and source-bound worksheets still contain identifiers and must remain with authorized people. Counts are never consent, authenticated evidence, security findings or grants.

## Source-only proof / known delivery boundary (20 October 2026)

The original source builder **already ran successfully in a separate permitted zSSH checkout** against exact pinned `0f76f2f`, with **60 original source files** intact and generated a **483,223-byte ZIP**, SHA-256:

`60f9086490ecb00d725ae00da173ee6eb843de9d346d4c39b5f4a51a359703de`

Original generated `index.html` SHA-256: `99c4f5f8fa7b96d246471faa2bcb30480d08f7a755906b54decbfb436c55623b`.

**Those generated assets are not yet committed in this separate distribution directory:** the connected VPS checkout refused creating the new destination directory. The authoritative result delivered by this PR so far is the reproducible production packager. Do not tell operators the new ZIP is already downloadable from this branch until the actual outputs have been published and inspected. No workaround for the VPS filesystem denial was attempted.

## Original release fence remains intact

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** No merge to main, active scan, target interaction, grant, production deploy or verified consent. Mandatory original exact-head hosted CI, permanently registered named VPS CI, original source owners, separate security/privacy/browser review, #177/#182/#829, actually authenticated current client/operator consent with action-time revocation and explicit HUMAN GO remain fully required. This independent distribution should stay a **draft stacked on PR #1680** until all relevant gates are met. No QA/regression/test suites were written or run.
