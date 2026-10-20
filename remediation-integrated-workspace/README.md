# LightUp — Integrated PRIVATE offline remediation suite

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD.** This is source-only offline software, not a released scanner, grant, authenticated evidence or verified remediation.

## Integrated original products

This branch includes existing original product assets unchanged from:
- [PR #1670](https://github.com/Zennay/Lightup/pull/1670): source-free recipient workload, comparison, HUMAN recipient journal, revision history and offline recipient browser.
- [PR #1661](https://github.com/Zennay/Lightup/pull/1661): complete original PRIVATE evidence relationship workrooms and independent source admission.
- [PR #1665](https://github.com/Zennay/Lightup/pull/1665): HUMAN Portfolio Studio and selective password-encrypted offline HUMAN action handoffs.
- Their pinned independent Casework and Evidence Artifact Ledger sources.

All **79 original software assets** are pinned by source-lock.json against the exact upstream source HEADs 6246550821039b829dc10ded95a1432c0653786f and 264bf15929e1f36699ea4114b91c5c313e55eea7. Original branch files are not rewritten. Their owners retain review authority.

## One-command offline installation

On an authorized trusted Linux machine with Python 3, inside a copy of this branch create a private parent directory first:

    mkdir -p "$HOME/lightup-private"
    chmod 700 "$HOME/lightup-private"
    python3 remediation-integrated-workspace/install.py build --output-dir "$HOME/lightup-private/integrated-workspace-v1"

The installer returns 2 = REVIEW_ONLY after local success, or 3 = HOLD on failure. Use an unused directory name. Open integrated-workspace-v1/index.html locally.

The new **private, 0700** folder contains the original 79 software-only files, a CSP/scriptless index linking four complete offline original application screens, source-lock.json, software-only.zip, and a SHA-256 manifest. The ZIP is ordered reproducibly and contains software, the installer, operator guide and landing page, but **no tenant data, evidence, login, credentials, private source workrooms or HUMAN notes**. All installed files are 0600. Never unpack or share this package outside a separately approved private environment. Optional original CLI cryptography functionality retains its documented local optional dependencies.

To check the installed folder's exact native file inventory and the locally generated software archive, without contacting any service:

    python3 remediation-integrated-workspace/install.py inspect --workspace "$HOME/lightup-private/integrated-workspace-v1"

Inspection enforces private file ownership/modes, regular nofollow one-link files, canonical warning and non-authority flags, exact installed SHA-256 file contents, ZIP-member byte identity, original source inventory and local scriptless portal renderer. It only establishes local consistency.

## Operator flow: maintain privacy boundaries

1. ORIGINAL SOURCE OWNER: open the offline index and use original Casework and Evidence Ledger. Review and prepare PRIVATE source-ledger workspaces using remediation-evidence-bundle-integrity/prepare.py per original operator guide. Original private records stay with the authenticated and separately authorized source owner. The human-only source-free PRIVATE Cockpit is an **explicitly separate** disclosure surface.
2. AUTHORIZED SOURCE-FREE RECIPIENT: on a trusted private destination re-admit a complete received source-free Cockpit with remediation-evidence-bundle-integrity/read_cockpit.py. Use remediation-recipient-trend/receiver_desk.py for anonymous workload series, locally human-ordered review and editable follow-up journals; use the standalone HUMAN Portfolio Studio to route anonymous follow-ups.
3. PRIVATE SELECTIVE HUMAN HANDOFF: use remediation-human-handoff/browser.html only for chosen recipient-appropriate source-free HUMAN action subset and, where required, local password encryption. The encrypted file does not authenticate the sender or authorize any action. Do not forward a full private owner workspace when only selected HUMAN questions are needed.

Native exact CLI commands and encrypted file/password handling are in the original adjacent README documents. Neither the launcher nor installer automatically executes scan, retest, remediation, grant, uploads, API calls or a consent decision.

## Actual non-authorization and release contract

Local SHA-256 source pins, manifests and zip checks are **unsigned and unkeyed**. They do not prove who authored source files, customer identity, legitimate consent, real evidence, fix, time order, security risk, verified retest or authority to act. Local encrypted browser files authenticate only their own ciphertext against the chosen passphrase and documented format; they do not authenticate real client/operator identity.

This is a DRAFT/HOLD composition branch, not a production merge. Required original gates remain: **exact-head hosted and permanent named VPS CI, original source-owner and independent security/privacy/browser/crypto review, original issues #177/#182/#829, genuine separately authenticated current client and operator consent with action-time revocation, and explicit HUMAN GO**. Until then: no merge to main, no production deploy, no active targets or native Apply. No QA, regression or test suite is created or run by this change; direct build/package inspection is not CI or security proof.

## Native safe receipt of the portable software-only ZIP

On a **separately authorized** private machine, obtain the exact pinned current installer, receiver and source-lock files from this release branch through an independently trusted channel. Place the ZIP in an existing absolute owner-only 0700 directory as a 0600 one-link file. Never run code from an untrusted ZIP before admission. The packaged installer and receiver are included as an offline convenience, **not** independently authenticated code-signatures.

    python3 remediation-integrated-workspace/install.py receive --archive "$HOME/lightup-private/software-only.zip" --output-dir "$HOME/lightup-private/received-suite"
    python3 remediation-integrated-workspace/install.py inspect --workspace "$HOME/lightup-private/received-suite"

Receiving rejects unexpected/duplicate member paths, unsafe archive types, inflated assets, changed original source bytes, mismatched launcher/installer contents, and destination overwrite. It atomically creates a fresh private 0700 folder with original 0600 software and fresh unsigned local manifest. REVIEW_ONLY=2; HOLD=3. This is **not** a signed sender, current consent or verification of findings and it never loads private evidence or contacts a service.

## Integrated native HUMAN owner and recipient workflow

The separate `workflow.py` entry point builds on the original, unchanged source-owner `prepare.publish` / `handoff.prepare` and recipient `trend.publish` / `recipient_workload_series.publish` / `recipient_studio.publish`. Both paths publish their combined result only after every original native component has been admitted. A failed operation deletes only its newly allocated private staging folder; it never edits an original source folder or existing result. Return codes: 2 = REVIEW_ONLY, 3 = HOLD.

**Original private source owner:** source folder must contain the canonical `current.json` plus optional `previous.json` and `session.json`, as required by the original Evidence Relationship Desk. Use an existing owner-only 0700 parent and a new absolute output directory:

    python3 remediation-integrated-workspace/workflow.py owner-start --input-dir "$HOME/lightup-private/original-ledger" --output-dir "$HOME/lightup-private/owner-review-001"

This publishes `owner-review-001/original/` (FULL ORIGINAL PRIVATE, not shareable) and `owner-review-001/source-free-recipient/` (original exact source-free Cockpit, still PRIVATE and transferable *only* after real separate disclosure authorization). The top-level portal and HUMAN-only count summary are local. **Never share the parent directory.** Repeat `--input-dir` or add `--bundle` for 1-12 complete independent original source records; do not fabricate additional records.

**Separately authorized source-free HUMAN recipient:** two source-free canonical Cockpit packets allow a useful actual human-reason workroom; for 3-12 separately received packets the original native ordinal series replaces two-way comparison. Only HUMAN-selected order, not authenticated chronology or same-client membership:

    python3 remediation-integrated-workspace/workflow.py recipient-start --cockpit "$HOME/lightup-private/received-01" --cockpit "$HOME/lightup-private/received-02" --output-dir "$HOME/lightup-private/recipient-review-001"

The private result contains `source-free-report/` with original source-free counts and `human-studio/` with the original browser-editable HUMAN reason follow-ups and exportable local HUMAN journal. No customer identity, original evidence or case-level join is added. Open the generated `index.html` locally. A single received Cockpit can still be opened with native `read_cockpit.py` directly; the integrated recipient comparison does **not** manufacture a second cohort.

Neither workflow creates approval, grant, scan, exploitation, native Apply, verified mitigation, authenticated sender or real client consent. All pre-existing release gates remain unchanged.

## Single-file source-free HUMAN Cockpit handoff (UNENCRYPTED)

The separate `portable_cockpit.py` composes the original unchanged source-free `read_cockpit.inspect` with a strictly original-member-only, reproducibly ordered ZIP transport. **No original evidence, person/client ID, case notes, attached material or grant is copied. The human aggregate counts can nonetheless be sensitive. This `.luhz` is NOT encrypted, source-signed or authenticated. Never send it without actual independent recipient/disclosure permission.** The CLI never sends or uploads any bytes itself.

On a trusted original owner-private device, after `workflow.py owner-start`, create a fresh 0600 file in an existing 0700 private parent:

    python3 remediation-integrated-workspace/portable_cockpit.py pack --cockpit "$HOME/lightup-private/owner-review-001/source-free-recipient" --output-file "$HOME/lightup-private/approved-human-handoff-001.luhz"

On another separately approved recipient device, copy the archive into an owner-only private directory with 0600 file permissions; with the same trusted pinned LightUp software installed, receive it atomically in a **new** PRIVATE folder:

    python3 remediation-integrated-workspace/portable_cockpit.py unpack --archive "$HOME/lightup-private/approved-human-handoff-001.luhz" --output-dir "$HOME/lightup-private/received-01"

Before publishing, the recipient refuses duplicate, unexpected, unsafe or oversized archive paths; reads only original Cockpit HTML/JSON and its manifest; reconstructs every native page through the unchanged original renderer; and verifies the archive bytes remain unchanged. It preserves original source-free bytes exactly and never authorizes actions. Both commands return 2=REVIEW_ONLY or 3=HOLD. Archives are unsigned and can be replaced by an attacker controlling the distribution: source identity and real consent remain external gates. For actual confidentiality over untrusted transport, use an independently authorized secure channel; these files are not encrypted by LightUp.

## Complete one-Cockpit recipient workflow (included in this installer)

The packaged `workflow.py recipient-start` now works for **one through twelve real canonical source-free Cockpits**, instead of requiring a fabricated second comparison. With one packet it uses the original native Cockpit admission and the independently implemented `single_review.py`, then publishes the same private top-level recipient navigation and a saved HUMAN-only counts summary. With 2 packets the original native comparison/interactive recipient Studio is used; 3–12 packets use the existing native user-ordered series. All paths return REVIEW_ONLY or HOLD; no source authorizations or cases are invented.

    python3 remediation-integrated-workspace/workflow.py recipient-start --cockpit "$HOME/lightup-private/received-01" --output-dir "$HOME/lightup-private/one-cockpit-human-review-001"

The **single reviewer is now included in the software-only ZIP** with its sibling `single_review.js`, `single_brief.py` and `SINGLE_REVIEW.md` (not only as standalone GitHub files). The existing installer `build`, `receive` and `inspect` commands include the exact new product bytes. Open the new private `human-studio/index.html` offline to select HUMAN follow-up stages and download an original source-bound *plaintext* PRIVATE HUMAN journal. Reopen a saved journal in a NEW private directory with `single_review.py resume`, or turn that existing exact-source-bound journal into a scriptless owner-private follow-up HTML+JSON brief via `single_brief.py`. See the bundled `SINGLE_REVIEW.md` for native commands and handling.

**Privacy:** original source-free metadata does not prove the same underlying cases, source authenticity, client consent, verified remediation or grant. Plaintext HUMAN journal and brief can contain sensitive human notes; they are never uploaded, encrypted, sent or redacted by this feature. Disclose only after actual independent recipient permission. Existing source-only ZIP self-hashes are not signatures; no main merge, active target, native Apply or production release is authorized.

## One-step HUMAN workroom from privately received .luhz archives

The included `archive_workflow.py` combines the original portable source-free Cockpit receiver and the existing native recipient HUMAN workflow into ONE offline operator action. **No client records, source evidence, finding IDs or authenticated consent are imported or inferred.** An incoming `.luhz` is UNSIGNED and UNENCRYPTED; it must already have been securely delivered to a separately authorized HUMAN recipient as a 0600 file under an owner-only 0700 directory. Never treat merely receiving it as approval.

    python3 remediation-integrated-workspace/archive_workflow.py --archive "$HOME/lightup-private/received-human-01.luhz" --output-dir "$HOME/lightup-private/complete-human-receipt-01"

With a second or later separately received source-free archive, repeat `--archive` up to 12 times. The operation re-admits every original source-free archive with the native `portable_cockpit.unpack()` (including original native `read_cockpit.inspect()` and exact page renderer); repeated *identical* archives cannot masquerade as another review. It then builds either the one-Cockpit original HUMAN journal, the original two-packet comparison or a 3–12 native user-ordered series plus editable HUMAN workspace. All outputs are private inside a NEW 0700 folder; its root `index.html` links the human reviewer and first admitted original Cockpit. New `received-XX/` folders are source-free but PRIVATE. Nothing is uploaded or written back to source owners.

The whole receiving flow is assembled under a randomly named private staging directory and exclusively published once, only after all original native records and original browser artifacts have been admitted. Inputs stay untouched. Existing outputs are never overwritten. Original human-selected order is NOT authenticated chronology; no security fix, verified retest, sender authenticity, consent or grant is established. A bad archive keeps the entire workflow on HOLD, not a partial displayed review. The updated software-only installer ships this CLI together with all original pinned source applications and native operator commands.

## Optional confidentiality: encrypted source-free HUMAN Cockpit transfer

The new independent `encrypted_cockpit.py` uses the original **unchanged** source-free `read_cockpit.inspect` and exact native Cockpit member set before accepting any source bytes. It encrypts the canonical source-free ZIP entirely **in memory** under a new passphrase, using the optional local `cryptography` package: PBKDF2-HMAC-SHA-256, 600,000 derivation rounds, random 16-byte salt, AES-256-GCM and a separate fixed purpose-specific associated-data domain with a fresh random 12-byte nonce. The canonical envelope has strict exact fields, canonical base64, hard size limits, false-only authority flags and **no plaintext client/source metadata**. Original source-free counts can still be confidential. Plaintext ZIP files are never written by this feature; decryption passes in-memory bytes through native `portable_cockpit.unpack_bytes` and original source-free HTML/manifest admission before private atomic 0700/0600 publication.

Requires an interactive trusted offline terminal to enter/confirm a **unique 14–256-character NFC passphrase**; no password is accepted on command-line arguments or environment variables. Install the optional `cryptography` Python package only from a trusted local/provider distribution; the ordinary offline product remains stdlib-only. Use separate approved trusted source-owner and recipient devices:

    python3 remediation-integrated-workspace/encrypted_cockpit.py encrypt --cockpit "$HOME/lightup-private/owner-review-001/source-free-recipient" --output-file "$HOME/lightup-private/selected-human-counts-001.luhx"

    python3 remediation-integrated-workspace/encrypted_cockpit.py decrypt --archive "$HOME/lightup-private/selected-human-counts-001.luhx" --output-dir "$HOME/lightup-private/received-private-001"

The encrypted `.luhx` may be transported only after **separate actual disclosure permission**; deliver the passphrase through a different trusted channel. The encrypted envelope is not a digital signature or certified owner identity. Encryption protects this particular file only while it is secret; the extracted PRIVATE Cockpit is plaintext on disk (0700/0600). Forgotten passphrases cannot be recovered, compromised/weak passphrases may be guessed offline, and Python memory/swap/backups cannot be securely erased by this tool. No network, scan, grant, real consent decision, retest, model call or source owner writeback occurs. Returns REVIEW_ONLY=2 or HOLD=3. Independent security/privacy/crypto review and original exact-head CI and release gates remain required; this is a DRAFT feature, not a production security attestation.

## One-step encrypted archive → HUMAN workroom

The original native one-command `archive_workflow.py` now accepts **either** previously admitted, unencrypted original `.luhz` packets or separately encrypted `.luhx` source-free Cockpit envelopes. The two modes are deliberately mutually exclusive within one call. For encrypted sources it reuses the new purpose-bound PBKDF2/AES-GCM native decryptor with an interactive passphrase prompt **per archive**, then passes the decrypted in-memory ZIP straight into the unchanged source-free original Cockpit native receipt. There is no plaintext ZIP intermediate, target action, grant or scan. Only after all requested encrypted inputs have been authenticated with their passphrases, independently re-admitted and mapped to an original HUMAN reviewer does the parent private 0700 workroom publish atomically. A malformed/wrong-key archive causes HOLD, not partially published original packets.

    python3 remediation-integrated-workspace/archive_workflow.py --encrypted-archive "$HOME/lightup-private/approved-counts-01.luhx" --output-dir "$HOME/lightup-private/encrypted-human-receipt-01"

Multiple encrypted archives can be selected by repeating `--encrypted-archive` up to 12 times. Each can require a different passphrase and represents **only operator-selected count packets, not authenticated chronology**. The decrypted source-free Cockpit HTML/JSON and any later HUMAN notes remain plaintext inside that new private recipient folder. The external disclosure permission, device security, and independently validated source/release conditions are still required; a valid encrypted file alone never constitutes actual client/operator consent or signed sender identity. Both encrypted and unencrypted paths are HUMAN-only, DRAFT/HOLD and return 2=REVIEW_ONLY or 3=HOLD. Required optional `cryptography` package is not silently installed.

## Atomic no-clobber software installation and receipt

Both native software `install.py build` and `install.py receive` now use Linux `renameat2(RENAME_NOREPLACE)` for the final full-private-directory publication, mirroring the original Evidence Workroom's atomic exclusive publisher. They refuse an already-existing or concurrently created destination even when that destination is empty; no plain `os.rename` fallback may overwrite or replace it. The containing owner-private directory is synced after publication. A failed publication removes only the just-created random private staging folder and leaves both existing destinations and source package untouched. On platforms without this Linux atomic operation, these two offline software actions HOLD instead of degrading to replace-capable filesystem semantics. No original source-owner authorizations, CI gates, evidence records or client data are modified.

## PRIVATE encrypted HUMAN journal continuation

The full installed suite now contains `journal_vault.py` and `JOURNAL_VAULT.md`. A recipient can explicitly seal an already native-admitted, single-Cockpit HUMAN journal as a source-bound AES-256-GCM encrypted `.luhj`, resume the HUMAN editing browser from that encrypted original journal, generate a private scriptless follow-up brief, or rekey a journal without creating a plaintext intermediate file. Reopened browser/brief output still contains local **plaintext HUMAN notes** in owner-private 0700/0600 files; sealing does **not** delete the previously downloaded plaintext original. Use only with genuine separate permission. See [complete native CLI usage](remediation-integrated-workspace/JOURNAL_VAULT.md).

## Portable complete source-free HUMAN reviewer handoff

This installed offline suite includes **review_package.py** and [REVIEW_PACKAGE.md](remediation-integrated-workspace/REVIEW_PACKAGE.md). A trusted HUMAN owner can independently combine one admitted anonymous source-free Cockpit and the exact originally hash-bound local HUMAN journal into one AES-GCM encrypted portable `.luhp`, with native support for taking an already encrypted `.luhj` without a plaintext intermediate. The authorized recipient decrypts it and obtains a new private original source-free Cockpit plus a populated editable local HUMAN reviewer. It always enforces complete original native source-free admission and source-session-bound HUMAN notes. Decrypted resulting PRIVATE HTML/JSON contains plaintext sensitive HUMAN notes; this is not client consent or authority to act. All source-owner/HUMAN GO/CI/security/privacy/crypto gates remain unchanged.
