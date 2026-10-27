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

## Complete original + recovery workroom (one offline portal)

For an operator who already has the held original integrated-remediation source files checked out, the independent `integrate.py` composes a completely NEW self-contained owner-private suite using the **unchanged native original installer**. It **does not modify, overwrite, repack or relabel** the original integrated source owner's installed directory or source lock. A separate scriptless launcher gives direct local links to the original installed workroom and this recovery desk.

```sh
mkdir -p "$HOME/lightup-private"
chmod 700 "$HOME/lightup-private"
python3 remediation-private-backup/integrate.py \
  --output-dir "$HOME/lightup-private/original-plus-recovery-001"
# Return code 2 means REVIEW_ONLY source-only installation, not production approval.
# Open locally:
# $HOME/lightup-private/original-plus-recovery-001/START-HERE.html

# Later, reopen this same installed software using original source-owner
# inspection plus independent private recovery inventory admission:
python3 remediation-private-backup/integrate.py inspect \
  --workspace "$HOME/lightup-private/original-plus-recovery-001"
```

The new **inspect** workflow reopens a complete previously installed PRIVATE suite, rejects unexpected/missing files, changed bytes, symlinks/hardlinks, group-readable assets, malformed/duplicate manifest fields, incompatible CSP/JS bytes, and a modified scriptless portal. It **must** successfully call the original owner's unchanged `install.py inspect` on `original-suite/` before returning `REVIEW_ONLY=2`. Inspection establishes only unsigned local consistency, never trusted source ownership, client permission or safe release.

The independent composer requires Linux atomic no-replace directory publication, a trusted owner-private directory outside the checkout, and the original native `remediation-integrated-workspace/install.py` source. It delegates complete original source-lock admission to that pinned native installer; refuses its HOLD instead of bypassing it. It installs the original complete offline source software under `original-suite/`, copies only seven approved companion source files under `private-recovery/`, and creates one scriptless local portal and a **PRIVATE UNSIGNED** source digest inventory. No operator backup, tenant bytes, secrets or evidence are bundled automatically. The original installer returns its own REVIEW_ONLY status; neither checksum inventory authenticates real source or grants authority.

`integrate.py` has been committed as runnable product source; a full native integrated installation on a real owner-controlled private directory is still NOT claimed. Source-owner, CI and independent security/privacy/browser review are required before any main merge/deployment.

## Interactive original-private source selection (CLI)

Instead of manually typing individual paths, the opt-in **wizard** shows only directly contained eligible single-link, current-owner PRIVATE 0600 files in one explicit 0700 source directory. It does **not** recurse, select automatically, copy anything before explicit operator selection, or include existing `.lupb` archives. The human chooses at most 32 numbered files and then confirms a fresh archive password:

```sh
python3 remediation-private-backup/vault.py wizard \
  "$HOME/lightup-private/reviewer-01" \
  --output "$HOME/lightup-private/reviewer-backup-interactive-001.lupb"
```

Only the selected originals are encrypted; it never infers customer consent, source validity or whether selected data are safe to disclose.

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

## Browser-first complete PRIVATE backup, two-snapshot recovery and selective encrypted handoff

The committed [fully bundled offline browser](standalone.html) is a complete owner-operated workflow; an operator does **not** need an existing backup or CLI to get started. It is software-only and runs locally. It does not access LightUp tenant databases, automatically discover local folders, upload sources, authenticate original providers, grant access or trigger remediation.

1. Open a **trusted, locally held** `standalone.html`. Under **Create a new encrypted PRIVATE workroom archive**, explicitly choose 1–32 individual local files (2 MiB each, 16 MiB combined). No directory-selection permission is requested and nested encrypted backup files are refused. Enter and confirm a new independent 12+ character password, review the local confirmation, then download a **new password-encrypted `.lupb`**. Byte SHA-256, original filenames and sizes are bound into the canonical authenticated AES-GCM payload.
2. To resume a prior workroom, unlock **Archive A** with the original password; local filename inventory and PRIVATE text previews become available only after full original byte-level admission. You can explicitly download an individual original plaintext file, with a browser warning that its download destination might not be protected.
3. To review changes, independently unlock **Archive B** under its own password. The comparison shows ADDED/REMOVED/CHANGED/UNCHANGED, but the A/B order is *operator-chosen*, **not verified chronology**. Choosing **Prepare encrypted recovery of B's added/changed files** selects just the present changed/added original B bytes for the separate password-encrypted subset form; it does **not** download or publish anything without another explicit confirmation and a new password.
4. The selective encrypted subset flow can also be used manually to re-encrypt any selected original files. Browser selection/clear cancels stale in-progress decrypt/export work, releases application references, zeroes held Uint8Array buffers when possible and revokes local download URLs. JavaScript cannot guarantee OS/browser process-memory sanitization.
5. **Keep the browser download PRIVATE.** Unlike the Python CLI, ordinary browsers cannot enforce mode 0600/0700 for the download directory. All outputs remain operator-selected PRIVATE file material and **are not sanitized recipient disclosures**. Never send them without a separate explicit, legitimate disclosure and identity decision.

Both Python CLI and browser use the **same `lightup-private-human-backup/v1`** canonical archive format and PBKDF2-HMAC-SHA256/AES-256-GCM authenticated format with 600,000 rounds. No network, browser IndexedDB, localStorage, cookies, external libraries or remote static assets.

## Native password-authenticated A/B delta archive — no plaintext reconstruction

For a PRIVATE owner who has TWO independently password-encrypted workroom snapshots, the new `delta` command combines *literal* source-byte differences into a **third NEW independently password-encrypted archive**. It does not decrypt to a directory or overwrite the original snapshots. Use this when a human wants only selected workroom changes from the chosen second archive, not the full private originals.

```sh
python3 remediation-private-backup/vault.py delta \
  "$HOME/lightup-private/reviewer-backup-001.lupb" \
  "$HOME/lightup-private/reviewer-backup-002.lupb" \
  --output "$HOME/lightup-private/reviewer-changed-only-003.lupb"
```

Enter the independently required original A password and B password, type literal `YES` to deliberately choose the PRIVATE B-only/changed bytes, and confirm a **third new** password for the result. Both original snapshots must authenticate their entire canonical schema and original file hashes first. The archive contains only original B files that have no matching original A filename or whose **bytes or original filename case** differ. Unchanged B files are not included. Files that exist only in A are **not** translated into deleted, fixed, resolved or authorized cases; the local CLI merely displays an anonymous A-only file count. If there are no B-only/changed files the CLI refuses to create an empty/fabricated new snapshot.

The A/B order is selected by the operator and does **not** establish real-world chronology or legitimate disclosure to the B recipient. The new encrypted delta retains full original PRIVATE material for those selected files. All original source-owner, consent and security review HOLD gates still apply.

## Original PRIVATE source review and encrypted HUMAN follow-up (portable browser)

The [actually shipped offline recovery app](standalone.html) also supports an opt-in **side-by-side A/B original text reviewer** for previously password-authenticated sources. Select **Review source text** beside a file after unlocking both separate A/B snapshots, then separately confirm that PRIVATE material may be displayed on this trusted local screen. Content is displayed via escaped text nodes only, capped to the first 8 KiB per archive, with absent/binary source clearly identified. This is a visual **literal source comparison**, *not* a trusted timeline, genuine authorization or evidence of a verified remediation. Changing/clearing either original archive always clears the sensitive review preview.

The same offline app now includes **Owner-only HUMAN comparison notes**. After opening both private archives, a reviewer enters their own explicit 1–10,000-character note, picks a **new independent password**, confirms that the note is PRIVATE and nonauthoritative, and downloads a third **AES-GCM encrypted** `.lupb` containing a single original file `human-review-notes.json`. The JSON contains the manually entered observations and only the names, sizes and SHA-256 digests of the selected A/B inventories. **No original source evidence bytes are bundled.** The A/B order is user-selected, no claimed chronology, source approval, verified remediation, authenticated sender or customer consent. The encrypted original HUMAN note can later be opened/reviewed in the same recovery browser or via the existing `vault.py inventory/restore` CLI, after password authentication.

Changing or clearing a PRIVATE source cancels its in-flight decrypt/export, clears any pre-existing HUMAN note, and prevents stale observations from being accidentally attributed to the next selected A/B source. Global Clear and pagehide clear operator-entered HUMAN text, passwords and local application buffers when possible. JavaScript cannot guarantee operating-system/browser memory erasure or secure permissions for browser download directories; move new PRIVATE encrypted files promptly to a trusted owner-private location.

**Portable source-owner integration detail:** the [combined installer/inspector](integrate.py) preserves original `remediation-integrated-workspace/install.py` byte-for-byte. When an operator inspects a previously installed relocated workroom, the unmodified original native inspector requires `source-lock.json` in its source-tree module directory, while the installed native workspace carries it in its root. Our separate installer now builds an ephemeral, 0700 owner-private copy of only the **already installed ORIGINAL software source files** plus the **unchanged original installed source-lock bytes**, executes that original inspector over the unchanged original installed workspace, and destroys the ephemeral copy. If the original inspector refuses, the combined inspection remains HOLD; this is **not** a bypass, synthetic original signature, or additional release approval. No original source-owner files or PRs were edited.

## Immutable output & restore boundary

- The backup contains at most 32 explicitly selected files, each ≤2 MiB and ≤16 MiB combined. Symlink or hardlinked input, files not owned by the current user or with group/other permissions, the reserved REVIEW-ONLY.txt name, unsafe names, duplicate names including case-insensitive collisions, mutation during read, malformed/duplicate JSON keys, unknown envelopes, wrong passwords, altered ciphertext, changed payload bytes, oversized content and noncanonical inner JSON are HOLD. No directory traversal, autodiscovery or recursive collection.
- The archive is a single new 0600 file in an existing directory owned by this user with no group/other permission bits. Linux directory restore uses atomic NOREPLACE publication to avoid replacing even a concurrently created empty destination folder. A fully authenticated archive can also restore only exact selected original basenames using repeatable --only options (unknown or duplicate names HOLD; no output). The selected dataset is staged into a new sibling owner-only 0700 directory; each file is created 0600 and fsynced, and the directory is renamed to the final **unused** destination only after all files were admitted. Existing output paths are refused. The reserved REVIEW-ONLY.txt name cannot be supplied in an archive, so every restored folder always receives a PRIVATE literal HOLD warning.
- The inventory, private subset derivation and two-snapshot comparison require successful decryption before printing PRIVATE source basenames, hashes or differences. Both backup passwords are prompted separately; neither file chronology nor actual remediation can be inferred from the resulting differences. Outer metadata asserts all four non-authority flags as literal false.
- All operations return 0 only to mean local file operation completed, **not** a release authorization, accepted remediation or successful original evidence verification. Refused input returns **3/HOLD**.

## Release gates (unchanged)

No main merge/deploy, no active endpoint, model, exploit, grant, automatic remediation, retest or verified fix. Source-owner, independent security/privacy/crypto and browser review, exact-head original hosted and permanently registered named VPS CI, original #177/#182/#829, separately authenticated current client and operator consent with action-time revocation and explicit HUMAN GO remain prerequisites for a real release. This is an offline, unreviewed DRAFT/HOLD recovery tool; never treat a backup as customer permission.

**Scope ownership:** only `remediation-private-backup/` may change in this PR. Does not claim the existing integrated suite is safe to release; cryptography guarantees password-based confidentiality/integrity only within its assumptions.
