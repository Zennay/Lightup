# LightUp · PRIVATE source-free HUMAN recipient scheduler

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This is a standalone recipient-planning companion stacked on **unchanged** [integrated original suite PR #1673](https://github.com/Zennay/Lightup/pull/1673) at exact parent `60dae8cc37333e54cbd9612f9d53e33e14d440ec`. The implementation is isolated to **new** `remediation-recipient-scheduler/` files. Do not merge to main or deploy without all original mandatory gates.

## What the recipient can actually do

An independently authorized PRIVATE recipient can select **1–12 genuinely received original source-free Cockpit folders** and, optionally, the native `single_review.py` JSON HUMAN journal for each. The Python entry point invokes the **unchanged original** source-free Cockpit and source-bound HUMAN journal admission before doing anything else; it refuses a fabricated duplicate source packet. Each admitted original source-free reason/slot/count becomes a separate editable HUMAN task. It never joins recipients or client identities, treats separate packets as a trusted timeline, invents findings, upgrades any source severity or implies a fix.

The local scriptless portable `index.html` offers a filtered planning desk with one task per source-free original reason-group, human-only stage, human owner label, tentative due date, follow-up action and prior HUMAN note. It shows pending/answered (self-declared), overdue, ownerless and unscheduled counts. A separate preview-first bulk toolbar can assign or clear owners, add or clear tentative dates and change HUMAN stage **only for the current search/filter selection**; it requires explicit confirmation, maintains each unchanged original source record and offers guarded one-step undo. A separately confirmed **anonymous counts-only** export drops original source hashes, row descriptions, owner names, notes, and exact dates, but small cohorts can still be identifying.

Users can **download an encrypted private `.lurp` planning file**, authenticated internally by AES-256-GCM and a separate password-derived PBKDF2-SHA256 600,000-iteration key (random salt and nonce). Import checks the complete original packet SHA-256 keys, all source-free ordinal/reason/count records, exact source order, HUMAN-only fields and literal non-authority flags **before replacing the live editable plan**. Modified/missing original source files HOLD rather than silently reusing HUMAN notes. Encryption provides confidentiality of the locally written planning file with a suitable password, **not** real client/source/sender authentication. Password loss is irrecoverable. The resulting browser page itself contains source-free original counts and HUMAN notes if such a journal was supplied, so keep that local page PRIVATE too.

A separate explicitly confirmed **tentative all-day .ics** can be imported manually into a calendar. Events intentionally contain neither original targets, source paths, usernames, task text nor HUMAN notes; a calendar app may still transmit the anonymous date/reminders, so use only with separate actual recipient and calendar permissions. No API, network request, calendar connection, scanner, grant, remedial change, test, CI run, or deployment is triggered.

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

## Non-negotiable release boundary

Notion posture remains **Incubate / M3–M7 PLAN/LAB ONLY, DRAFT/HOLD**. Source hash checks and passwords do not establish source identity, approved recipient, actual consent, authentic risk, verified findings, remediation or retest. Do not use actual targets. No changes to the original Casework, recipient-trend, authorization/consent, scope, scanner, webapp, runner, CI or QA source. Before any main merge, deployment or active release the original exact-head hosted **and** permanent registered named VPS CI, original owner and independent security/privacy/browser/crypto reviews, original #177/#182/#829, separately authenticated current client+operator consent with revocation-at-use and explicit HUMAN GO remain mandatory.

No QA, regression or test suites are added or run by this work package. Lightweight production syntax/build inspection does not establish security approval.
