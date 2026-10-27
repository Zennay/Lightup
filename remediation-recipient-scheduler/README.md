# LightUp · PRIVATE source-free HUMAN recipient scheduler

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This is a standalone recipient-planning companion stacked on **unchanged** [integrated original suite PR #1673](https://github.com/Zennay/Lightup/pull/1673) at exact parent `60dae8cc37333e54cbd9612f9d53e33e14d440ec`. The implementation is isolated to **new** `remediation-recipient-scheduler/` files. Do not merge to main or deploy without all original mandatory gates.

## What the recipient can actually do

An independently authorized PRIVATE recipient can select **1–12 genuinely received original source-free Cockpit folders** and, optionally, the native `single_review.py` JSON HUMAN journal for each. The Python entry point invokes the **unchanged original** source-free Cockpit and source-bound HUMAN journal admission before doing anything else; it refuses a fabricated duplicate source packet. Each admitted original source-free reason/slot/count becomes a separate editable HUMAN task. It never joins recipients or client identities, treats separate packets as a trusted timeline, invents findings, upgrades any source severity or implies a fix.

The local scriptless portable `index.html` offers a filtered planning desk with one task per source-free original reason-group, human-only stage, human owner label, tentative due date, follow-up action and prior HUMAN note. It shows pending/answered (self-declared), overdue, ownerless and unscheduled counts. A separate preview-first bulk toolbar can assign or clear owners, add or clear tentative dates and change HUMAN stage **only for the current search/filter selection**; it requires explicit confirmation, maintains each unchanged original source record and offers guarded one-step undo. The recipient dashboard also displays a dedicated **per-HUMAN-owner workload board** (open, overdue and due-soon) with direct owner filtering. The next-seven-days view and locally calculated overdue grouping do not imply that original source-free packets have real dates or chronological order. A privacy-confirmed **scriptless printable PRIVATE agenda** can include only the currently visible tasks, with anonymous source-free reason categories, HUMAN owner/stage/deadline/action, and *optional independently confirmed PRIVATE notes*; it is never sent, emailed or authenticated by the app.\n\nA separately confirmed **anonymous counts-only** export drops original source hashes, row descriptions, owner names, notes, and exact dates, but small cohorts can still be identifying.

Users can **download an encrypted private `.lurp` planning file**, authenticated internally by AES-256-GCM and a separate password-derived PBKDF2-SHA256 600,000-iteration key (random salt and nonce). Import checks the complete original packet SHA-256 keys, all source-free ordinal/reason/count records, exact source order, HUMAN-only fields and literal non-authority flags **before replacing the live editable plan**. Modified/missing original source files HOLD rather than silently reusing HUMAN notes. Encryption provides confidentiality of the locally written planning file with a suitable password, **not** real client/source/sender authentication. Password loss is irrecoverable. The resulting browser page itself contains source-free original counts and HUMAN notes if such a journal was supplied, so keep that local page PRIVATE too.

The printable HTML agenda is explicitly **PRIVATE**, contains locally entered HUMAN owner/action information and may be identifying even though it omits original source identifiers. Store it under separate approved protection; do not hand it to another person merely because it has no source hashes.\n\nA separate explicitly confirmed **tentative all-day .ics** can be imported manually into a calendar. Events intentionally contain neither original targets, source paths, usernames, task text nor HUMAN notes; a calendar app may still transmit the anonymous date/reminders, so use only with separate actual recipient and calendar permissions. No API, network request, calendar connection, scanner, grant, remedial change, test, CI run, or deployment is triggered.

## Offline CLI on the original integrated source-only branch

Create a new output location below an **existing owner-only 0700** parent (one new location per run). Input folders and journals must already have passed the original documented consent/disclosure procedures; tool admission **does not** certify them.

```bash
python3 remediation-recipient-scheduler/schedule.py \
  --cockpit "$HOME/lightup-private/received-01" \
  --output-dir "$HOME/lightup-private/scheduler-01"
```

To combine **multiple** separate already received native folders and optionally carry each exact corresponding human journal:

```bash
python3 remediation-recipient-scheduler/schedule.py \
  --cockpit "$HOME/lightup-private/received-01" \
  --journal "$HOME/lightup-private/review-01/human-source-bound.json" \
  --cockpit "$HOME/lightup-private/received-02" \
  --journal - \
  --output-dir "$HOME/lightup-private/scheduler-02"
```

Use one `--journal` per `--cockpit` (a literal `-` means no journal), or omit all `--journal` parameters. Journal order must match Cockpit order. This tool specifically admits the native `single_review.py` **source-free single-Cockpit JSON HUMAN journal**, **not** an original evidence owner ledger, Casework packet, seven-column worksheet, encrypted vault directly or encrypted complete handoff package. First receive/decrypt genuine native packages using the unchanged documented integrated recipient workflow and only then pass the resulting original Cockpit + ordinary source-bound HUMAN journal (or no journal). No plaintext auto-extraction performed here.

Exit **2 = REVIEW_ONLY** on completed private software build, **3 = HOLD**. A successful review-only build is not a green security/release gate. The generated `index.html` and `README.txt` are locally private 0600 files in a 0700 directory. Open `index.html` directly in a Web Crypto-capable offline browser. Browser activity stays in memory until explicitly downloaded. Use the encrypted download before closing the tab; prompted passwords are not stored. A real recipient who receives a plaintext source-free browser bundle still needs their own authenticated disclosure consent.

## Source-exact private HUMAN continuation when packets change

The browser has two deliberately different encrypted `.lurp` imports. **Open encrypted plan** restores only when the entire ordered current original source-free packet set and every original reason/slot/count are identical. A mismatch does not touch the current HUMAN workroom. **Carry unchanged source-bound HUMAN plan forward** admits a previously saved encrypted plan after password verification; it strictly checks the original closed HUMAN schema, declared original SHA-256 digest, full group/ordinal/count membership and non-authority flags, then previews how many **genuinely byte-identical original packets** can be carried across operator-selected packet reordering. Only after explicit confirmation does it copy HUMAN owner, date, stage, local next-action and notes for matching original packets. New, absent or changed packets remain as currently admitted and **are never marked fixed, authorized or reconciled**. Save a new encrypted checkpoint after carrying.

The previous private checkpoint may have a different packet ordering or set, but a reused packet digest alone is an **unsigned local equality check, not a genuine source/customer signature**. Carry never changes any original received Cockpit or evidence owner record. No automatic closure, email, calendar write, retest or remote sharing.

## Non-negotiable release boundary

Notion posture remains **Incubate / M3–M7 PLAN/LAB ONLY, DRAFT/HOLD**. Source hash checks and passwords do not establish source identity, approved recipient, actual consent, authentic risk, verified findings, remediation or retest. Do not use actual targets. No changes to the original Casework, recipient-trend, authorization/consent, scope, scanner, webapp, runner, CI or QA source. Before any main merge, deployment or active release the original exact-head hosted **and** permanent registered named VPS CI, original owner and independent security/privacy/browser/crypto reviews, original #177/#182/#829, separately authenticated current client+operator consent with revocation-at-use and explicit HUMAN GO remain mandatory.

No QA, regression or test suites are added or run by this work package. Lightweight production syntax/build inspection does not establish security approval.

## Full original native archive → scheduler + recipient reviewer (new)

Run `archive_schedule.py` from a complete clone of this stacked branch after genuine separate recipient/disclosure authorization. It invokes the **unchanged original native** `portable_cockpit.unpack` or `encrypted_cockpit.decrypt`, re-admits each unchanged original source-free packet, creates the existing original `workflow.recipient_start` reviewer and our new private scheduler, then atomically publishes a **single** private portal. An encrypted `.luhx` packet is decrypted directly into the native original private recipient directory through memory, **without writing a plaintext intermediate ZIP**. Do not send the resulting folder to unauthorized recipients; it contains native source-free material and may contain HUMAN notes.

For native original unencrypted `.luhz` transfer packets, each already stored as a regular 0600 file in a trusted original-private 0700 directory:

```bash
python3 remediation-recipient-scheduler/archive_schedule.py \
  --archive "$HOME/lightup-private/handoff-01.luhz" \
  --archive "$HOME/lightup-private/handoff-02.luhz" \
  --output-dir "$HOME/lightup-private/recipient-with-schedule-01"
```

For **encrypted** native source-free Cockpit `.luhx` and corresponding native **encrypted original single-Cockpit HUMAN journal vault `.luhj`**, the CLI interactively asks the original native passphrase(s) and does not write a plaintext journal intermediate:

```bash
python3 remediation-recipient-scheduler/archive_schedule.py \
  --encrypted-archive "$HOME/lightup-private/handoff-01.luhx" \
  --journal-vault "$HOME/lightup-private/human-01.luhj" \
  --output-dir "$HOME/lightup-private/recipient-with-schedule-02"
```

Alternatively use `--journal` for the original canonical source-bound `single_review.py` plain JSON journal. For multiple archives, supply **exactly one** `--journal` or `--journal-vault` per archive in the same order; use literal `-` for a packet without corresponding journal. Do not mix encrypted/plain archive selectors or journal types in the same command. Original native admission checks the exact source-bound packet before adopting HUMAN notes. Wrong passphrases, changed bytes, mismatched original records and duplicate real packets reject the complete new output. Existing prior outputs and the input archives/vaults stay unchanged.

Private resulting product: `index.html` links to `human-scheduler/index.html` (editable HUMAN planning and encrypted `.lurp` checkpoints), `original-human-review/index.html` (unchanged native original recipient reviewer), and `original-sourcefree-01/index.html` (unchanged native original source-free Cockpit). A separate `private-summary.json` contains **only** generic counts, false authority flags and a warning; no original packet source hashes/IDs or HUMAN notes. The original browser may still separately offer other operator workflows. This native integration is strictly **local-only, plan/lab, PRIVATE and non-authorizing**, never CI signoff, client consent, release, or proof of a fix.

## Browserless reopening of the exact encrypted PRIVATE scheduler plan

`schedule_vault.py` is a separate **offline native read-only HUMAN delivery** for operators who cannot use the browser to print their previously **browser-encrypted** `.lurp` plan. Supply the **same ordered exact admitted original source-free Cockpit directories** that were used when saving the `.lurp` in the browser. Original `single_review.original` admission is reused; a source packet, order, slot, original reason or count mismatch fails closed without writing a report. Reordered packets need the browser's explicit HUMAN carry workflow first and a **new encrypted checkpoint**; the native CLI never guesses correspondence.

```bash
python3 remediation-recipient-scheduler/schedule_vault.py \
  --vault "$HOME/lightup-private/old-human-schedule.lurp" \
  --cockpit "$HOME/lightup-private/recipient-with-schedule-02/original-sourcefree-01" \
  --output-dir "$HOME/lightup-private/human-agenda-reopened-01"
```

The local CLI prompts for the `.lurp` password through an interactive private terminal. It checks its 0600 owner-only ciphertext file and closed envelope, PBKDF2-HMAC-SHA256 600,000 iteration and AES-256-GCM opening, exact browser JSON encoding, literal false authority, every original source-free sha256, human row/slot/count and bounded local follow-up values. A new 0700/0600 private folder contains a **scriptless printable HTML HUMAN agenda** (without the sensitive original HUMAN notes by default) and a source-ID-free anonymous human-counts JSON. Explicitly add `--include-notes` only when separately authorized to include confidential HUMAN notes in the local HTML; add `--calendar` for an optional, anonymous and tentative all-day `.ics` **file**. These are local outputs, not actual calendar events or messages sent to someone else. Nothing is restored into original source-owner or original recipient workspaces. Non-authorizing, no online operation or source changes.

The browser's explicit source-matching carry must be used for plans whose original packets change or are reordered; importing a previous `.lurp` into a different source without exact matching is **not** native-authorized. A locally rendered HUMAN plan may include personally identifying HUMAN owner labels and notes: it stays PRIVATE, requires independent recipient/disclosure consent, and is not evidence that anything was fixed. The original exact-head release gates remain unsatisfied.

## Complete additive software-only distribution

The new `bundle.py` builds a separate **PRIVATE offline software-only** LightUp distribution without rewriting the original integrated source owner. It first calls the original `remediation-integrated-workspace/install.py` to generate and re-inspect the exact pinned original native suite. The original full manifest and unmodified original `software-only.zip` remain in `original-native-suite/`. A separate `software/` tree collects all original pinned runnable files alongside **only our own scheduler companion**, with a new readable scriptless `index.html` start page. A standalone deterministic `remediation-scheduler-software-only.zip` contains the runnable merged software, without any original client packets, scans, passwords or HUMAN state. `bundle-manifest.json` records exact original manifest and software member hashes for local consistency; unkeyed SHA-256 is **not** trusted authentication.

Create an **already-authorized**, existing owner-only 0700 destination parent, then:

```bash
python3 remediation-recipient-scheduler/bundle.py build \
  --output-dir "$HOME/lightup-private/sourceonly-scheduler-bundle-01"
python3 remediation-recipient-scheduler/bundle.py inspect \
  --workspace "$HOME/lightup-private/sourceonly-scheduler-bundle-01"
```

The finished `index.html` explains the original evidence workroom and **actual native recipient archive intake**; the zip contains only software. Unpacking `remediation-scheduler-software-only.zip` requires an independently trusted transport and a PRIVATE destination. After extraction, execute `python3 remediation-recipient-scheduler/archive_schedule.py` **from the extracted software tree** against original, independently permitted source-free handoffs; no fabricated findings are included.

The source-only bundle generator is committed but **not claimed as successfully built on the named VPS**: the connected zSSH user was refused permission to create the chosen private build-parent folder. This denial was respected without alternate-path bypass. Original exact-head CI and independent owner/security/privacy/browser/crypto reviews still remain separate HOLD gates.

## Focused private HUMAN work queues from an encrypted checkpoint

The native `schedule_vault.py` can now produce **owner-scoped or date-scoped** scriptless agendas from an existing browser-encrypted `.lurp` plan, after re-admitting the complete unchanged original source-free packet inventory. Filtering occurs **only after full original source admission**. No source member is silently altered or dropped from the underlying checkpoint, and no original source-free join or verified finding is invented.

To publish one human owner's pending work, without including private notes:

```bash
python3 remediation-recipient-scheduler/schedule_vault.py \
  --vault "$HOME/lightup-private/old-human-schedule.lurp" \
  --cockpit "$HOME/lightup-private/received-01" \
  --owner "Review coordinator" --pending \
  --output-dir "$HOME/lightup-private/owner-agenda-01"
```

Other supported filters: `--unassigned`, `--overdue`, `--due-next-days 7`, or `--stage ask_source_owner`. A due-next-day range is limited to 0–90 days and excludes already answered HUMAN-only tasks; overdue applies only to self-reported still-open tasks. Conflicting date/owner filter pairs HOLD; an empty matching work queue does not generate a misleading empty report. Use `--calendar` only if the selected tasks have tentative dates; optional `--include-notes` adds sensitive HUMAN text and needs actual independent recipient approval. Output remains owner-only PRIVATE; filtering is not authenticated disclosure permission.


## Atomic receipt of the complete software-only bundle (no unsafe unzip)

The new `bundle_receive.py` reconstructs the **merged runnable original + scheduler software-only ZIP** on an independently trusted, offline Linux host, in a newly created PRIVATE 0700 directory with 0600 files. Unlike a generic unzip, receipt applies an exact original pinned source inventory, **closed original-native runtime file list**, exact locally trusted companion file bytes, exact portal/source lock, safe ZIP member types and modes, bounded uncompressed member sizes and manifest SHA-256 matching. Duplicate, extra, changed or malformed entries HOLD without final output. This is only local software consistency, never cryptographic sender provenance, original owner permission, security review or release authority.

The trusted source-only `bundle_receive.py` + original installer/companion code and `bundle-manifest.json` must be obtained via a **separately trusted authenticated distribution channel**; never execute or trust code merely because it arrived in the same unverified ZIP being inspected. Keep both the `remediation-scheduler-software-only.zip` and separately obtained `bundle-manifest.json` in an existing owner-only 0700 folder as 0600 regular one-link files, then from the separately trusted original source checkout:

```bash
python3 remediation-recipient-scheduler/bundle_receive.py \
  --archive "$HOME/lightup-private/remediation-scheduler-software-only.zip" \
  --manifest "$HOME/lightup-private/bundle-manifest.json" \
  --output-dir "$HOME/lightup-private/received-complete-scheduler-01"
```

Open the new private `index.html`; the resulting tree contains executable **software source only**, not any personal/customer/evidence packets. The generated owner-private launch page explains how to hand off genuine separately permitted source-free original `.luhz/.luhx` Cockpits through the unchanged original native receiver and into the new HUMAN planner. No remote code, consent, scanning, grant, test, QA workflow or native Apply is invoked. A software package is not production-releasable until ALL original release gates have actually been passed.

## PRIVATE password interaction

The source-free HUMAN browser now requires an accessible, **masked** offline `type=password` modal for new encrypted `.lurp` saves, exact-source resume, and change-aware source-bound carry. The previous visible browser `prompt` text entry was replaced. Password entry is kept only in the current browser dialog's in-memory state, not persisted to cookies, localStorage, URL or telemetry. Downloading an encrypted checkpoint no longer silently marks the HUMAN plan safely persisted: the operator must separately confirm that the private download is stored in a protected local location. A declined confirmation preserves the unsaved-change warning. Neither this acknowledgment nor a password proves actual sender, recipient, client authority or consent.


## NEW: complete native password-encrypted Cockpit + HUMAN journal -> integrated planner

For **already authorized original** `.luhp` transfers produced by unchanged original `remediation-integrated-workspace/review_package.py create`, the new [`complete_handoff.py`](complete_handoff.py) removes the manual two-file handoff steps. It accepts 1–12 actual complete native encrypted PRIVATE source-free Cockpit+exact HUMAN journal packets, one interactive original password per packet. It uses the **unchanged native** `review_package.incoming`, `review_package.open_sealed`, `review_package.unpack_inner`, `portable_cockpit.unpack_bytes`, `journal_vault.original` and `single_review.admit_journal` before adding any scheduling state.

```bash
python3 remediation-recipient-scheduler/complete_handoff.py \
  --review-package "$HOME/lightup-private/original-complete-01.luhp" \
  --review-package "$HOME/lightup-private/original-complete-02.luhp" \
  --output-dir "$HOME/lightup-private/received-complete-human-schedule-01"
```

On a trusted authorized offline machine, open the new PRIVATE `index.html` to access the integrated HUMAN planner **plus** the unchanged native source-free HUMAN recipient reviewer and each original one-Cockpit HUMAN journal. Original reason count, exact source-bound HUMAN stage and private human notes are carried into the corresponding planner task only after full native admission. The output is published as one fresh owner-private 0700 directory with regular 0600 files. Modified encrypted packets, wrong passphrases, duplicate exact source-free packets, incorrect original journal lineage or untrusted original ZIP members fail closed without a published partial recipient workroom.

**Important confidentiality:** original complete encrypted handoff stays encrypted as input, and its internal plaintext ZIP/journal exists only in memory during parsing, but the resulting deliberately opened reviewer and planner HTML are **plaintext PRIVATE** files containing sensitive HUMAN notes. This software is not an authenticated sender, client, consent, source evidence or grant; the receiving person must already have real separate authorization. Original notes are not automatically sent anywhere. Do not copy the entire decrypted output tree to another party.

This native complete handoff entry point is included in the additive software-only `bundle.py` inventory and strict `bundle_receive.py` closed member checks. All original security/privacy/crypto/browser review, hosted/named VPS CI, explicit HUMAN GO and independently verified current client+operator consent requirements remain DRAFT/HOLD.


## NEW: native source-exact carry-forward into a changed packet selection

When a recipient has a prior privately browser-encrypted `.lurp` HUMAN schedule and now receives **a new separate set or ordering of truly original source-free Cockpit directories**, the new [`carry_native.py`](carry_native.py) can prepare a fresh native PRIVATE offline scheduler. It uses unchanged original source-free `single_review.original` admission and the existing browser-encrypted `.lurp` native reader before proposing any carry. The full previous HUMAN packet schema, authority=false flags, original source SHA-256 digests, reason group counts and every individual slot/reason/count/HUMAN-only owner, note, stage, date and action value are required.

```bash
python3 remediation-recipient-scheduler/carry_native.py \
  --vault "$HOME/lightup-private/previous-private-human.lurp" \
  --cockpit "$HOME/lightup-private/recent-original-01" \
  --cockpit "$HOME/lightup-private/recent-original-02" \
  --output-dir "$HOME/lightup-private/private-human-carry-01"
```

The native CLI first asks the LOCAL private passphrase in a protected terminal, prints an aggregate preview of exact source digest matches versus new/changed packets and requires the HUMAN operator to type **CARRY** before exclusively publishing a new 0700/0600 workroom. No existing ciphertext or original source-free folder is modified. All previously recorded HUMAN assignments/notes/stages are carried only when the **entire original source-free digest and its full reason/slot/count membership exactly match**. Changed, new or absent sources **never** inherit prior HUMAN decisions or automatically become marked fixed. The new selected ordering is bound to the newly generated browser seed; save a **new** encrypted `.lurp` using the offline masked password modal to persist the revised version.

Only local HUMAN history carries forward. This is not cryptographic signer identity, proof that two packets belong to one client, chronological ordering, verified source finding, actual consent or authorization. A 0700 workroom and password do not replace separately approved recipient access, source-owner permission, hosted/named CI, independent review or HUMAN GO.


## NEW: selected-only PRIVATE HUMAN follow-up, without transferring any original source

The offline scheduler now has **Encrypt selected HUMAN-only handoff (visible tasks)**. After the operator chooses filters, the browser shows a disclosure warning and allows independent choices about whether to include any HUMAN owner labels or private HUMAN notes (both **excluded by default**). It creates a new masked-password AES-256-GCM, PBKDF2-SHA256 (600,000 iterations) encrypted `.luhq` file with only the chosen locally HUMAN task category/stage/tentative date/next action and separately included notes/labels.

The `.luhq` **deliberately excludes every original source SHA-256, Cockpit packet/ordinal, original slot, source count, case/client identity, raw evidence and source-owner material**. The source is intentionally **not reconstructible or independently verifiable** from this file. It cannot serve as a verifiable finding, authenticated sender, consent receipt, approved recipient identity, retest, permission, grant or verified remediation. HUMAN labels and dates may remain identifying, especially for small selections: separate real client/operator recipient and disclosure consent is still required.

The recipient, using the independently authenticated trusted LightUp software on a private authorized Linux machine, saves the file as a single-link 0600 regular file in an existing 0700 PRIVATE folder, then opens it **locally without any source evidence**:

```bash
python3 remediation-recipient-scheduler/queue_handoff.py \
  --handoff "$HOME/lightup-private/approved-selected-followup.luhq" \
  --output-dir "$HOME/lightup-private/received-human-followup-01"
```

The receiver requires the passphrase interactively, checks exact closed source-redacted schema, fixed false authority/consent/source-auth flags, bounded HUMAN labels and local original source-free reason vocabulary, and decrypts the AES-GCM envelope in memory. It exclusively creates an owner-private `index.html`, a **scriptless read-only PRIVATE follow-up HTML** and an anonymous count/field-inclusion receipt. It never reconstructs a source-free Cockpit, writes original evidence, performs a scan/retest/remediation or establishes actual recipient permission. Keep the handoff passphrase in a separately approved channel and delete local plaintext follow-up files only according to established retention rules. Password loss has no recovery path. The complete software-only bundle/strict source-only receiver include the new `queue_handoff.py` runtime.

