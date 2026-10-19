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

## Operational posture

The output is **human-supplied local file bytes matched against source-reported HUMANS**, **not** signed chain of custody, verified scanner evidence, validated security impact, remediation success, or consent. Treat any original severity or retest text as unverified source labels. Existing mandatory original exact-head hosted + permanently registered named VPS CI, source-owner review, independent privacy/security/crypto review, original #177/#182/#829, current independent client/operator consent with action-time revocation for future active work and explicit HUMAN GO remain necessary. This independent feature must stay **DRAFT/HOLD**, without main merge or production deployment, until actual release gates are satisfied.

There are deliberately **no new tests, QA scripts, permission grants or CI overrides** in this companion. Only direct Python syntax and CLI/build inspection are appropriate under the 17 October execution policy.
