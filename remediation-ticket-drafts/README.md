# LightUp · Private Remediation Ticket Desk

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Entirely offline HUMAN planning; no authentic grant, client/operator consent, evidence verification, scan, remediation execution, retest result, issue publication or release decision.

## What the operator can actually do

1. Start from an **already authenticated, tenant-authorized** original LightUp finding-summary CSV produced through the existing `lightup.finding_export_cli` or the already authorized Casework handoff CLI. The exact columns are `finding_id,title,severity,retest_status,remediation`. Do not import raw evidence, client secrets, target addresses or credentials.
2. Open [the portable standalone app](standalone.html) locally (or `index.html` from the intact source-owner checkout). No server, npm, external JavaScript, browser storage, cookies, API access or network. Strict original `LightUpCasework.parseCSV` validates the complete UTF-8 CSV before any state update: max 1 MiB, 350 findings, no duplicates. The original source owner parser is **byte-for-byte SHA-256 pinned** to `c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225` from held PR #1568, commit `9c73e8468ce271bf8c6bef4cac071e5ad9c1806b`.
3. Select critical/high, filtered or individual findings. Each has an editable HUMAN owner alias, tentative date, non-conclusive work stage, next engineering action, future independent verification plan and blocker. Source severity, retest status, finding title/ID and original proposed remediation are **read-only source labels**. No source database or file mutation occurs.
4. **Optional existing Casework import:** after loading the exact original CSV, import an original `lightup.remediation_casework_draft` JSON saved by the source-owner Casework board. The new strictly bounded, duplicate-key-rejecting JSON parser first admits the entire native original packet with unmodified `LightUpCasework.loadPacket`. Its non-authority flags must remain literally false; the exact original canonical SHA-256, complete membership and all five original finding fields must match the CSV. Admission is all-or-nothing. The operator explicitly approves replacing current local HUMAN notes. The previous Casework `completed` or `deferred` HUM​AN stage resets to **triage**, and `ready_for_retest` becomes **ready for human review**; these are never a verified retest. Previous private Casework `note` and `updated_utc` are deliberately not exported to tickets.
5. Preview GitHub-flavoured Markdown **locally**. Each human ticket includes exact unsigned source canonical and byte hashes, original labels, proposed owner and next action, and explicit non-authorization notices. Markdown punctuation and HTML delimiters are escaped before plaintext export. Nothing is posted or created automatically.
6. With independent private-channel/recipient review and a separate download confirmation, save a **PRIVATE plaintext** selected ticket or selected multi-ticket Markdown bundle. It contains original finding identifiers, titles, proposals and HUMAN notes and is sensitive. Do **not** post publicly or treat any copied file as authenticated authority. A **separate anonymous JSON counts export** contains severity/retest label counts only, no IDs/titles/owner/hashes. Use **Forget** to discard in-tab private content; previously downloaded copies require separate handling.

## Portable build

From a checkout based on the **immutable** original Casework owner PR #1568, plus this ticket-desk branch:

```sh
python3 remediation-ticket-drafts/build_standalone.py \
  --output /trusted/private/path/lightup-PRIVATE-tickets.html
```

The builder refuses any change to original Casework parser bytes, embeds source and new scripts with exact `sha256-...` CSP script hashes, keeps `connect-src 'none'`, and writes an exclusive owner-private `0600` output; existing destinations are never overwritten. The committed `standalone.html` is a ready-to-open convenience snapshot. Its SHA-256 is recorded in the associated PR.

**Private local files** are still plaintext if not separately encrypted. Use an approved private storage location and verify recipients. The app cannot establish authentic CSV sender, ongoing client authority, consent, independent reviewer identity, real remediation or real retest. Source hashes detect accidental local mismatch, **not** cryptographic sender authenticity. Browser memory and file:// isolation are not a substitute for an approved workstation or secret store.

## Ownership and release

New-only paths in `remediation-ticket-drafts/`, based on original source-owner `#1568` at immutable SHA `9c73e8468ce271bf8c6bef4cac071e5ad9c1806b`. Does **not** modify original source, active workers' files, production models, scopes, scanners, grants, consent, web sessions, CI, QA or tests.

**DRAFT/HOLD. No main merge, deploy, real targets, scanner use or GitHub issue posting.** Original exact-head hosted and permanently registered named VPS CI, original source-owner acceptance, independent security/privacy review, #177/#182/#829, authentically separate current client/operator consent with revocation at action time, and explicit HUMAN GO remain mandatory. Local checkboxes, unsigned SHA-256, imported saved HUMAN stages and privately written Markdown do **not** replace any gate.
