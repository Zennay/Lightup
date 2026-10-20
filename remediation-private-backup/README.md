# LightUp · PRIVATE HUMAN Workroom Backup & Restore

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent offline companion to the **held, unmerged** integrated evidence-remediation source [PR #1673](https://github.com/Zennay/Lightup/pull/1673) at immutable commit `a7cab0f0911d6cf4f413a8eac5a4d7b17fccc61d`. This folder is new. Source-owned Casework, Evidence Ledger, evidence receivers, authorization, scanning, CI and security policies are untouched.

## Purpose: recover private human work without generating authority

A human operator deliberately selects **1–32 individual ordinary local files** from their PRIVATE offline workroom. This CLI encrypts exact bytes, original basenames, sizes and SHA-256 digests into one owner-only `.lupb` archive. It supports authenticated PRIVATE inventory, atomically restoring all or only explicitly chosen original files to **a new owner-only folder**, password rotation to a **distinct new archive** without producing plaintext files, an independent **encrypted minimum-necessary subset**, and a **two-snapshot authenticated PRIVATE change desk** that reports file names added, removed, changed and unchanged without pretending that a changed file means a verified fix. Neither operation changes the original input files or existing archive.

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

# Optional minimum-necessary recovery: only one original name
python3 remediation-private-backup/vault.py restore \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  "$HOME/lightup-private/reviewer-selective-recovery" \
  --only human-decisions.csv

python3 remediation-private-backup/vault.py rotate \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  --output "$HOME/lightup-private/reviewer-backup-002.lupb"

python3 remediation-private-backup/vault.py compare \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  "$HOME/lightup-private/reviewer-backup-002.lupb"
```

The passwords are prompted interactively and **never accepted as CLI arguments or environment variables**; create and rotate require a confirmation. Use distinct strong passwords and a secured device. Losing the password loses access; this program does not offer a recovery backdoor or password logging. Old archives are never overwritten/deleted, including after re-encryption.

## Ready-to-open PRIVATE offline browser (no server)

[Open the shipped portable one-file recovery desk](standalone.html) after saving a trusted copy locally, or use the original two-file [index.html](index.html) with [browser.js](browser.js) beside it. The portable HTML is deliberately **script SHA-256 CSP pinned**, `connect-src 'none'`, with no external scripts, network, cloud, browser storage, HTTP endpoints or source grants. Browser JS lives in memory; decrypting or comparing does **not** upload data.

Offline operator flow:

1. Open `standalone.html` **from a locally verified copy**, on a trusted device. Select an existing original `.lupb` and enter its password. The browser independently checks the canonical archive version, fixed false authority flags, password-authenticated AES-GCM source bytes, exact size bounds, and every source SHA-256 before displaying a single original file.
2. Optionally open a second archive with a separate password; compare literal file names and byte hashes. Differences are **not** proof of work completion, risk changes, consent, identity or chronological order.
3. Explicitly preview only a text file, or confirm downloading an original plaintext file to the browser's download destination. **Browser downloads cannot enforce 0700/0600 permissions.** Move downloaded PRIVATE files into correctly protected offline storage.
4. For safer minimum-necessary recovery, tick one or more verified source files and choose a NEW independent password. The browser downloads a **freshly encrypted** compatible `.lupb` containing only those original selected bytes. This is not an approved disclosure, a release, or authorization to send the archive to another party. Passwords are never accepted by URL or stored in browser localStorage/cookies.
5. Use **Clear** after finishing to drop application references; full guaranteed memory erasure is not provided by browser or JavaScript runtimes.

Build a newly pinned standalone browser from the checked-out local product files into an unused PRIVATE destination when source JS changes:

```sh
python3 remediation-private-backup/build_browser.py \
  --output "$HOME/lightup-private/recovery-standalone-v2.html"
```

The builder emits SHA-256 CSP for the **exact source** `browser.js`, and refuses to overwrite existing app files. The shipping `standalone.html` is an actual complete, static HTML artifact for immediate offline use, not an unbuilt preview. Since owner and independent browser/cryptography reviews are outstanding, the app is still **DRAFT/HOLD**.

## Re-encrypt only the minimum necessary files (CLI)

The CLI can derive an entirely new encrypted PRIVATE archive from a previously authenticated original, without first restoring unencrypted files. For example:

```sh
python3 remediation-private-backup/vault.py subset \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  --only human-decisions.csv \
  --output "$HOME/lightup-private/reviewer-subset-001.lupb"
```

It asks for the old password and a **new password with confirmation**, authenticates all original bytes before narrowing the selected files, generates fresh salt/nonce, and never mutates either original files or original archive. It **does not** validate legitimate recipient identity, actual consent or disclosure authority.

## Immutable output & restore boundary

- The backup contains at most 32 explicitly selected files, each ≤2 MiB and ≤16 MiB combined. Symlink or hardlinked input, files not owned by the current user or with group/other permissions, the reserved REVIEW-ONLY.txt name, unsafe names, duplicate names including case-insensitive collisions, mutation during read, malformed/duplicate JSON keys, unknown envelopes, wrong passwords, altered ciphertext, changed payload bytes, oversized content and noncanonical inner JSON are HOLD. No directory traversal, autodiscovery or recursive collection.
- The archive is a single new 0600 file in an existing directory owned by this user with no group/other permission bits. A fully authenticated archive can also restore only exact selected original basenames using repeatable --only options (unknown or duplicate names HOLD; no output). The selected dataset is staged into a new sibling owner-only 0700 directory; each file is created 0600 and fsynced, and the directory is renamed to the final **unused** destination only after all files were admitted. Existing output paths are refused. The reserved REVIEW-ONLY.txt name cannot be supplied in an archive, so every restored folder always receives a PRIVATE literal HOLD warning.
- The inventory, private subset derivation and two-snapshot comparison require successful decryption before printing PRIVATE source basenames, hashes or differences. Both backup passwords are prompted separately; neither file chronology nor actual remediation can be inferred from the resulting differences. Outer metadata asserts all four non-authority flags as literal false.
- All operations return 0 only to mean local file operation completed, **not** a release authorization, accepted remediation or successful original evidence verification. Refused input returns **3/HOLD**.

## Release gates (unchanged)

No main merge/deploy, no active endpoint, model, exploit, grant, automatic remediation, retest or verified fix. Source-owner, independent security/privacy/crypto and browser review, exact-head original hosted and permanently registered named VPS CI, original #177/#182/#829, separately authenticated current client and operator consent with action-time revocation and explicit HUMAN GO remain prerequisites for a real release. This is an offline, unreviewed DRAFT/HOLD recovery tool; never treat a backup as customer permission.

**Scope ownership:** only `remediation-private-backup/` may change in this PR. Does not claim the existing integrated suite is safe to release; cryptography guarantees password-based confidentiality/integrity only within its assumptions.
