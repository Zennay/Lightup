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
