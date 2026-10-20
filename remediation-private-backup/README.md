# LightUp · PRIVATE HUMAN Workroom Backup & Restore

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent offline companion to the **held, unmerged** integrated evidence-remediation source [PR #1673](https://github.com/Zennay/Lightup/pull/1673) at immutable commit `a7cab0f0911d6cf4f413a8eac5a4d7b17fccc61d`. This folder is new. Source-owned Casework, Evidence Ledger, evidence receivers, authorization, scanning, CI and security policies are untouched.

## Purpose: recover private human work without generating authority

A human operator deliberately selects **1–32 individual ordinary local files** from their PRIVATE offline workroom. This CLI encrypts exact bytes, original basenames, sizes and SHA-256 digests into one owner-only `.lupb` archive. It supports authenticated PRIVATE inventory, atomically restoring the original selected files to **a new owner-only folder**, and password rotation to a **distinct new archive** without producing plaintext files. Neither operation changes the original input files or existing archive.

The format binds complete canonical JSON via AES-256-GCM authenticated encryption, a random salt and nonce, and PBKDF2-HMAC-SHA256 with 600,000 rounds. No network, server, cloud key management, local browser storage, runner, scanner, target discovery, tenant authentication or consent request. Requires Python 3.10+ with `cryptography` available in the trusted offline environment.

This is **not** the original evidence producer/validator and **not a sanctioned disclosure exporter**. The user-selected PRIVATE data may include personal data, targets, secrets, original evidence and other sensitive material. The filename or content hash never certifies source-free data, reliable source identity, actual human identity, security findings, fix proof, permission or consent. **Do not send/share a backup, even encrypted, without a separately legitimate disclosure decision.** Prefer the original source-free selective handoff for recipients; do not use a whole owner-workroom backup as a recipient packet.

## Commands (real files, trusted offline host)

Prepare an owner-only parent *outside the Git checkout*:

```sh
mkdir -p "$HOME/lightup-private"
chmod 700 "$HOME/lightup-private"

python3 remediation-private-backup/vault.py create \
  --output "$HOME/lightup-private/reviewer-backup-001.lupb" \
  "$HOME/lightup-private/reviewer-01/human-decisions.csv" \
  "$HOME/lightup-private/reviewer-01/recipient-notes.json"

python3 remediation-private-backup/vault.py inventory \
  "$HOME/lightup-private/reviewer-backup-001.lupb"

python3 remediation-private-backup/vault.py restore \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  "$HOME/lightup-private/reviewer-01-recovered"

python3 remediation-private-backup/vault.py rotate \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  --output "$HOME/lightup-private/reviewer-backup-002.lupb"
```

The passwords are prompted interactively and **never accepted as CLI arguments or environment variables**; create and rotate require a confirmation. Use distinct strong passwords and a secured device. Losing the password loses access; this program does not offer a recovery backdoor or password logging. Old archives are never overwritten/deleted, including after re-encryption.

## Immutable output & restore boundary

- The backup contains at most 32 explicitly selected files, each ≤2 MiB and ≤16 MiB combined. Symlink input, unsafe names, duplicate names including case-insensitive collisions, mutation during read, malformed/duplicate JSON keys, unknown envelopes, wrong passwords, altered ciphertext, changed payload bytes, oversized content and noncanonical inner JSON are HOLD. No directory traversal, autodiscovery or recursive collection.
- The archive is a single new 0600 file. A restored dataset is staged into a new sibling owner-only 0700 directory; each file is created 0600 and fsynced, and the directory is renamed to the final **unused** destination only after all files were admitted. Existing output paths are refused. The optional text marker is PRIVATE and is not produced if an original file already uses its name.
- The inventory command requires successful decryption before it prints any original names or SHA-256 values. Outer metadata asserts all four non-authority flags as literal false.
- All operations return 0 only to mean local file operation completed, **not** a release authorization, accepted remediation or successful original evidence verification. Refused input returns **3/HOLD**.

## Release gates (unchanged)

No main merge/deploy, no active endpoint, model, exploit, grant, automatic remediation, retest or verified fix. Source-owner, independent security/privacy/crypto and browser review, exact-head original hosted and permanently registered named VPS CI, original #177/#182/#829, separately authenticated current client and operator consent with action-time revocation and explicit HUMAN GO remain prerequisites for a real release. This is an offline, unreviewed DRAFT/HOLD recovery tool; never treat a backup as customer permission.

**Scope ownership:** only `remediation-private-backup/` may change in this PR. Does not claim the existing integrated suite is safe to release; cryptography guarantees password-based confidentiality/integrity only within its assumptions.
