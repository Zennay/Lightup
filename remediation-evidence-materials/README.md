# LightUp · PRIVATE encrypted evidence material handoff

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Not a security release, verified vulnerability, retest, client consent, grant, scan or permission to contact a target.**

The original Evidence Artifact Ledger deliberately records **SHA-256 fingerprints, not the actual evidence bytes**. This independent companion closes the missing offline transfer loop: an operator may manually select up to twelve *already indexed original HUMAN evidence files*, bind their actual bytes against an existing original encrypted HUMAN Ledger, and create a new passphrase-protected 0600 transfer. A recipient with their own **current LightUp account/tenant/engagement read** and a matching encrypted original HUMAN workspace may decrypt and extract to a fresh owner-private folder. Neither operation changes the LightUp database, original Ledger, source owners, HUMAN statuses or network targets.

## Preconditions and boundaries

- Run on a trusted Linux workstation from this branch (and its pinned original owner ancestors) with existing LightUp Python dependencies. It reuses the **unchanged** `remediation-evidence-bridge/workspace.py`, `remediation-evidence-bridge/merge.py`, `remediation-secure-export/secure_export.py`, and original AES-256-GCM/PBKDF2 `remediation-ticket-vault/vault.py`.
- The sender and recipient must each have their own currently permitted account/engagement **read access**, demonstrated through original `DomainStore` login and the exact original five-column findings CSV bytes. This read access is **not permission to scan, grant, deploy, retest or publish**.
- Both parties must have a source-matching *original* encrypted Unified HUMAN workspace `.ltv` with the same **complete attachment inventory**, obtained through the existing owner-controlled workflow. Any attachment addition, source revision, client/engagement mismatch or original inventory change produces HOLD until a fresh legitimate matching baseline is provided.
- Passphrases are prompted **only through an interactive private terminal**. The sender's **new material-transfer passphrase must differ from the original encrypted HUMAN-workroom passphrase**; reuse is refused. Never put them in arguments, shell history, documentation or CI. Do not email the passphrase alongside the material.
- The selector JSON, actual selected file bytes, HUMAN `.ltv` and received `.ltv` must be original owner-owned, ordinary **0600 files** (no symlinks or hardlinks). The fresh destination must be beneath an existing real **0700 owner-private directory**. Directories or group-readable input files are refused.
- **Maximum 12 files; 2 MiB per file; 2.5 MiB aggregate; 4 MiB original vault envelope.** Larger material should stay with the original trusted owner under a separately approved transfer process. The original Ledger itself allows bigger individual local fingerprints, but this companion intentionally fails closed rather than streaming unreviewed sensitive data.
- This is **private raw evidence**, unlike the fingerprint-only ledger. Extracted files remain potentially dangerous/untrusted. Do not execute or render extracted bytes automatically. Only anonymous counts are printed to the terminal; filename, original finding references and hashes appear only **inside encrypted output** and the **private extracted receipt**. All original filenames are replaced with neutral `material-01.bin` paths on disk.

## Faster source-index selection (no manual SHA transcription)

The added source-authenticated **interactive selection assistant** reads the current original encrypted HUMAN Ledger under the same real account/tenant/engagement check and prints an escaped, PRIVATE terminal index of the original registered attachments. Choose one to twelve ordinal numbers and manually provide each existing owner-private 0600 absolute local file. Before writing a new exclusive 0600 selection, it verifies **each actual file byte size and SHA-256 against the current native original ledger record**; any mismatch holds the whole output. The `pack` command independently checks again after the selection is saved, so changed material cannot silently slip into a later transfer.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/selection.py \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --output /private/lightup/NEW-selection.json \
  --ack-private-selection
```

The operator does not need to copy SHA fields manually. Terminal output is confidential source-associated HUMAN metadata and must not be captured in public logs. This tool never downloads, discovers or scans endpoints and never changes the original HUMAN record or its stage.

## Recommended: single-step private sender and receiver workflows

For a human-friendly operation, the complete sender/recipient path no longer needs separately created plaintext `selection.json` or duplicate original-source authentication during the same operation:

**Sender** — `send.py` uses the real original account/tenant/engagement read, opens the exact current encrypted original HUMAN attachment index once, shows numbered original registered file metadata, prompts for 1–12 explicitly chosen owner-private real files, checks SHA-256/size, and **reopens/rechecks all file bytes again just before encrypting**. It creates only a **new original vault-compatible AES-256-GCM 0600 `.ltv`**, without writing a selector to disk.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/send.py \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --output /private/lightup/NEW-material-transport.ltv \
  --ack-private-material
```

**Recipient** — `receive.py` requires its own currently permitted original account/engagement read, and an exact original encrypted HUMAN attachment inventory. The recipient opens the encrypted material once, enters explicit PRIVATE HUMAN receipt status and optional notes for each original file, then creates **a NEW encrypted 0600 recipient return `.ltv`** and a **NEW 0700 private folder with 0600 neutral file data and original receipt**. If extraction fails, the newly created reply is removed; existing originals are not modified. The resulting encrypted reply can be returned separately to the sender for independent current-source matching.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/receive.py \
  --db /private/lightup/existing.sqlite \
  --email recipient@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/received-material-transport.ltv \
  --output-dir /private/lightup/NEW-received-material \
  --reply-output /private/lightup/NEW-private-human-reply.ltv \
  --ack-private-material
```

These are **human-controlled passive local file operations**. They never authenticate the recipient's notes as a cryptographic identity signature, claim evidence provenance, change original HUMAN records, grant scope, initiate scanning, or verify a remediation. The original separate `selection.py`, `transfer.py pack/unpack`, and `reply.py prepare` interfaces remain available for staged workflows.

## 1. Select actual local indexed material

Create an explicit **owner-only 0600** `/private/lightup/selection.json` using the *existing exact-original HUMAN Ledger* record's `finding_id` and `sha256`. Paths must be absolute files chosen manually by the legitimate evidence owner; the tool does not search folders or contact endpoints.

```json
{
  "kind": "lightup.private_local_material_selection",
  "schema_version": 1,
  "items": [
    {
      "finding_id": "ORIGINAL_FINDING_ID",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "/private/lightup/source-proof.bin"
    }
  ]
}
```

This is a **shape example only**, not a genuine record. A real digest and byte size must match the original HUMAN Ledger attachment exactly, or packaging fails.

## 2. Sender: encrypt actually selected bytes

```bash
PYTHONPATH=src python3 remediation-evidence-materials/transfer.py pack \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --selection /private/lightup/selection.json \
  --output /private/lightup/NEW-evidence-materials.ltv \
  --ack-private-material
```

The tool reauthenticates first, opens and validates the original encrypted HUMAN workspace and the full original attachment membership, rehashes every actual private local file, and only then makes a **new exclusive 0600 original-vault-encrypted** transfer. No plaintext intermediate disk file, no browser, HTTP request, DNS, scanner, model call or automatic original HUMAN Apply.

## 3. Recipient: reauthorize and extract only exact-matching material

The recipient must have their own valid existing LightUp login and a matching original encrypted HUMAN workroom. Receiving a transfer does **not** provide authorization to access a different client.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/transfer.py unpack \
  --db /private/lightup/existing.sqlite \
  --email recipient@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --package /private/lightup/received-evidence-materials.ltv \
  --output-dir /private/lightup/NEW-received-evidence \
  --ack-private-material
```

The receiver's original current source and full original HUMAN Ledger inventory must match the received encrypted source identity. The tool rejects duplicate JSON keys, noncanonical content, other-than-literal-false authority flags, unknown IDs, mismatched material names/sizes/digests, duplicate finding+hash pairs and over-limit payloads **before creating a folder**. The new 0700 folder gets neutral `material-XX.bin` 0600 files and a 0600 `PRIVATE-receipt.json` mapping the original registered HUMAN labels to those neutral local names. A failed partial publication removes all newly written output; prior encrypted originals are untouched.

## 4. Later PRIVATE local continuity review

A recipient can independently reopen its **already extracted** folder at a later date. This human-only product operation reauthenticates the current original client/engagement source through LightUp, decrypts the existing original source-bound HUMAN inventory, admits the 0600 receipt with exact canonical JSON, rejects any unexpected file in the directory, and rehashes **every** neutral received file against the original registered original finding/file index. The result reports only anonymous local match counts or **HUMAN HOLD**; it does not certify origin, repairs, security outcomes or permission.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/recheck.py \
  --db /private/lightup/existing.sqlite \
  --email recipient@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --folder /private/lightup/NEW-received-evidence \
  --ack-private-review
```

Any source revision, changed original attachment, altered or missing file bytes, receipt tampering, unexpected file in the folder, access mismatch or public filesystem permissions fail closed. The original source and private files remain unchanged. This is an **operator feature**, not a QA or test suite.

## 5. Recipient HUMAN encrypted reply (never a retest verdict)

The original encrypted material workflow now has a **two-way human follow-up**. Once `transfer.py unpack` creates its private folder, the recipient signs into the actual original LightUp account and opens their matching current original HUMAN workspace. `reply.py prepare` re-admits the original encrypted material and compares every extracted local file **byte-for-byte** to that material and its exact source-bound native receipt, then prompts the human for one explicit status and optional private note **per received file**. Status choices are only `received_unverified`, `needs_human_followup`, or `human_hold`. It creates a new 0600 encrypted `.ltv` containing **no evidence file bytes**, only bounded original IDs/SHA-256, human status/notes, current original source+HUMAN-inventory identity and an exact SHA-256 of the encrypted-transfer plaintext. A fresh passphrase distinct from the earlier workspace and transport passphrases is mandatory.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/reply.py prepare \
  --db /private/lightup/existing.sqlite \
  --email recipient@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/received-evidence-materials.ltv \
  --folder /private/lightup/NEW-received-evidence \
  --output /private/lightup/NEW-recipient-human-return.ltv \
  --ack-private-receipt
```

The sender receives the **encrypted reply** separately and must independently present their **own original-current READ**, the identical original encrypted transport, an identical original HUMAN source/inventory, and the reply's passphrase. The default review prints **only nonidentifying HUMAN status counts**. Add `--ack-private-details` only on an owner-private interactive terminal to deliberately display source labels and private notes.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/reply.py inspect \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/sent-evidence-materials.ltv \
  --reply /private/lightup/received-recipient-human-return.ltv \
  --ack-private-receipt
```

This authenticated current-source READ **does not digitally sign the recipient's identity** or certify where material was collected, whether a finding exists, whether a fix succeeded, or that active activity is permitted.

## 6. Stage recipient follow-up in ORIGINAL HUMAN Request Desk (separate manual Apply)

The new **native follow-up bridge** `followup.py` transforms only reply rows explicitly marked `needs_human_followup` into existing original HUMAN Request Desk v1-shaped `followup_question` records. It conservatively groups multiple files into one question per **original finding**, refuses oversize HUMAN notes and the native 200-request ceiling, and **does not add duplicates when that finding already has a non-closed original HUMAN request**. Original Casework, Evidence Review, local attachment index, prior human request statuses and notes are retained unmodified.

First view privacy-minimized counts:

```bash
PYTHONPATH=src python3 remediation-evidence-materials/followup.py preview \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/sent-evidence-materials.ltv \
  --reply /private/lightup/received-recipient-human-return.ltv \
  --ack-private-followup
```

After human review, run `carry` with the exact same arguments **plus** `--output /private/lightup/NEW-original-human-followup.ltv`; type `STAGE HUMAN DRAFT` and choose a **new private passphrase**. The result is **another, separate encrypted 0600 original-compatible Unified HUMAN v2 workspace** containing only newly appended `human_stage=draft` request suggestions with the recipient's private notes. It never changes the previous encrypted workroom or original app/database. The operator must still separately `open-current` this source through the original owner application, use its native original source-bound **Preview**, and manually confirm **Apply** if and only if the HUMAN owner chooses. No native automatic import/Apply and no security verdict.

The return packet is **encrypted notes from a human**, not third-party identity proof, client consent, signed custody or a verified remediation.

## 7. Ready-to-open PRIVATE offline receipt inbox

`inbox.py` closes the receiver-to-owner HUMAN communication loop with a readable, responsive **single-file scriptless HTML** generated only after real original-current account/client/engagement read, exact source-bound native attachment admission, and decrypted original-material and recipient-reply matching. It groups private HUMAN replies as **HOLD**, **needs HUMAN follow-up**, or **received but unverified**, highlights original **source-claimed** critical/high severity and retest labels without upgrading them to facts, and shows private notes only inside the explicitly chosen 0600 local HTML file. It includes a restrictive CSP (`default-src 'none'`, `script-src 'none'`, `connect-src 'none'` and SHA-256-pinned local CSS), no external resources, no active scripts, no data uploads, and no browser persistence. It never opens evidence bytes or applies original HUMAN actions.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/inbox.py \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/sent-evidence-materials.ltv \
  --reply /private/lightup/received-recipient-human-return.ltv \
  --output /private/lightup/NEW-private-human-receipt-inbox.html \
  --ack-private-html
```

Open the new HTML **locally on a trusted owner-only workstation**. It contains confidential original finding titles, IDs, hash references and HUMAN notes; never place it in a webserver, cloud-synced or publicly accessible folder. Source identity was authenticated **only at the moment this private HTML was created**; it is not ongoing access, approved scope or a security verdict.

## 8. Multi-recipient PRIVATE HUMAN team conflict desk

A sender working with several independent recipients can now combine **two to twelve existing encrypted transport/recipient-reply pairs** into a single scriptless owner-private review desk. `team.py` requires **one real original-current LightUp account/client/engagement read and identical complete original encrypted HUMAN attachment inventory**, followed by individual private passphrases and exact original source/material binding for each reply. The original encrypted bytes are only decoded in process and are never written into the team HTML; source labels, file SHA-256 and HUMAN notes are PRIVATE local content.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/team.py \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/transfer-one.ltv --reply /private/lightup/reply-one.ltv \
  --transfer /private/lightup/transfer-two.ltv --reply /private/lightup/reply-two.ltv \
  --output-dir /private/lightup/NEW-private-team-review \
  --ack-private-team-html
```

The operator gets **NEW 0700 directory** containing a **0600 `index.html`** (private offline status cards, conflicting HUMAN statuses side-by-side, source-claimed severity/retest clearly unverified, individual notes retained) and **0600 `anonymous-counts.json`** (no finding/recipient/source IDs, names or hashes; HUMAN counts only). Conflicting statuses are **never majority-voted or silently resolved**. Entries are labelled by input packet ordinal, **not authenticated reviewer identity**; alias/timestamp fields remain human-supplied. All static HTML is scriptless, CSP-pinned and offline; no file content, endpoints, grants, scans, verified fixes, browser persistence or automatic original HUMAN Apply.

This is private collaboration with source-specific HUMAN notes, not a third-party security certification or a release approval.

## 9. Native ORIGINAL HUMAN follow-up from several encrypted replies

The multi-recipient collaboration desk also has a **separate, explicitly acknowledged native HUMAN Request Desk staging flow**. `team_followup.py preview` opens the exact original CURRENT tenant/engagement, native encrypted HUMAN source and 2–12 exact encrypted material/reply pairs, then reports only **anonymous** proposal counts. A finding receives at most one new native `followup_question` draft if one or more recipients explicitly request follow-up or if separate recipients disagree about HUMAN status. It preserves **all divergent notes/statuses per packet** instead of voting on the truth. Existing original HUMAN requests that are still open are never duplicated; any note too long for the original native 1,400-character limit, native record mismatch or full original request capacity causes complete HOLD, never a partially truncated or silently resolved note.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/team_followup.py preview \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/transfer-one.ltv --reply /private/lightup/reply-one.ltv \
  --transfer /private/lightup/transfer-two.ltv --reply /private/lightup/reply-two.ltv \
  --ack-private-team-followup
```

Only after separate HUMAN review, run `team_followup.py stage` with the **same** source/pair flags and `--output /private/lightup/NEW-private-team-human-drafts.ltv`. The operator must enter `STAGE TEAM FOLLOWUP` and a new private passphrase. This writes a **new exclusive 0600 encrypted original-compatible Unified HUMAN workspace**, preserving every original Casework/Evidence/attachment and old request unchanged and appending only `human_stage=draft` questions. No note, document or original app is silently applied. The original source-bound Ledger still requires its **separate native Preview and manual HUMAN Apply**. A conflicting review is a human question, **not** a verified vulnerability, remediation, cryptographic recipient identity or client authorization.

## 10. Encrypted portable multi-recipient HUMAN desk with present-source reopening

The dedicated **`team_bundle.py`** offers a secure handoff for the HUMAN collaboration result itself. Instead of exporting private original findings and notes directly to an HTML file, **`seal`** performs the same real current LightUp account/client/engagement read and 2–12 independently decrypted source-bound transfer/reply validations as `team.py`, then stores only the **bounded original finding + local fingerprint + HUMAN status/note metadata** into a **NEW exclusive owner-private 0600 AES-256-GCM `.ltv`** with the original protected vault. Actual evidence file bytes are **never** included. There is no plaintext intermediate, no shell credentials/passphrases and the new password **must differ from every original HUMAN source, transfer and recipient reply passphrase**.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/team_bundle.py seal \
  --db /private/lightup/existing.sqlite \
  --email operator@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --transfer /private/lightup/transfer-one.ltv --reply /private/lightup/reply-one.ltv \
  --transfer /private/lightup/transfer-two.ltv --reply /private/lightup/reply-two.ltv \
  --output /private/lightup/NEW-encrypted-human-team.ltv \
  --ack-private-team
```

A receiving operator with their **own permitted current account/tenant/engagement READ** and **their own currently source-matched encrypted original HUMAN workspace** may reopen the team handoff **without receiving the original evidence bytes or each previous encrypted reply**. `open-current` decrypts the team bundle, enforces exact original source CSV digest, client+engagement, COMPLETE original SHA attachment inventory, native original file membership, bounded canonical HUMAN records, no duplicate source packet/file and literally false authority flags, then builds the same scriptless offline private team desk only in a **new owner-only 0700** directory. An independent `inspect` command displays only source-bound anonymous HUMAN packet/conflict counts without plaintext HTML publication.

```bash
PYTHONPATH=src python3 remediation-evidence-materials/team_bundle.py inspect \
  --db /private/lightup/existing.sqlite \
  --email recipient@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --input /private/lightup/received-encrypted-human-team.ltv \
  --ack-private-team

PYTHONPATH=src python3 remediation-evidence-materials/team_bundle.py open-current \
  --db /private/lightup/existing.sqlite \
  --email recipient@example.invalid \
  --client-id CURRENT_CLIENT --engagement-id CURRENT_ENGAGEMENT \
  --human /private/lightup/current-original-human.ltv \
  --input /private/lightup/received-encrypted-human-team.ltv \
  --output-dir /private/lightup/NEW-human-team-view \
  --ack-private-team
```

The team bundle authenticates its encryption and exact original **source and file index continuity**, not external reporter identity or actual provenance: HUMAN alias, timestamp and conclusions remain unverified reviewer claims. Once original finding source or attachment inventory changes, `open-current` fails closed until a legitimately source-matched original workspace is available. No client permission, scope grant, vulnerability proof, verified repair, authorized retest, scan or original native HUMAN Apply is conferred.

## Operational posture

The output is **human-supplied local file bytes matched against source-reported HUMANS**, **not** signed chain of custody, verified scanner evidence, validated security impact, remediation success, or consent. Treat any original severity or retest text as unverified source labels. Existing mandatory original exact-head hosted + permanently registered named VPS CI, source-owner review, independent privacy/security/crypto review, original #177/#182/#829, current independent client/operator consent with action-time revocation for future active work and explicit HUMAN GO remain necessary. This independent feature must stay **DRAFT/HOLD**, without main merge or production deployment, until actual release gates are satisfied.

There are deliberately **no new tests, QA scripts, permission grants or CI overrides** in this companion. Only direct Python syntax and CLI/build inspection are appropriate under the 17 October execution policy.
