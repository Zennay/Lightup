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

Inspection enforces private file ownership/modes, regular nofollow one-link files, canonical warning and non-authority flags, **the exact complete 79 pinned-original + 25 integrated-tool inventory** (never just whichever files a received manifest happens to list), exact installed SHA-256 file contents, ZIP-member byte identity, original source inventory and local scriptless portal renderer. The installed ZIP and the receiver must both preserve the builder's deterministic path order, original 2020 timestamps, Unix 0600 regular-file attributes, DEFLATE compression, and empty member/archive comments, encryption flags and extra metadata. Incomplete or rewritten ZIP layouts are HOLD, even when content hashes happen to match. These are local byte-integrity checks, **not** cryptographic signatures or authenticated software provenance.

## Reproducible software evidence — single-command PRIVATE passport

To bind the installed offline evidence/remediation software to the **exact current
checkout**, explicitly select an existing installed suite and an unused output
directory beneath an existing owner-only 0700 parent:

```sh
python3 remediation-integrated-workspace/install.py inspect \
  --workspace "$HOME/lightup-private/integrated-workspace-v1" \
  --compare-checkout \
  --report-dir "$HOME/lightup-private/software-passport-v1"
```

This completes the local offline integrity workflow without making any network
requests: verify every 0600 installed software file and the archive inventory,
compare the pinned original software and the integrated CLI/browser assets to
the exact current checked-out bytes, and publish a separate **0700, no-overwrite**
report directory with 0600 `REVIEW_ONLY.json` and scriptless `REVIEW_ONLY.html`.
The report contains anonymous software counts, the declared original source
commit references, two unsigned archive/manifest checksums, and literal FALSE
authorization/release flags. It deliberately omits tenant inputs, evidence,
findings, source paths, reviewer names and notes; no source file is copied to
the report. Missing, replaced, symlinked or changed files produce HOLD without
publishing an incomplete passport.

The native `private_desk.py inspect-checkout` operation and offline operator
UI expose the same explicit command. The regular `inspect` command still works
without a passport; omit `--compare-checkout` only when inspecting a detached
package that cannot be compared with an original checkout. That condition is
reported as **not checked**, never as passed.

The builder and recipient now use stable no-follow source admission, re-admit
the pinned source lock and integrated software before publishing, and inspect
the **complete newly staged suite** against the exact checkout before
exclusively publishing the destination. A failed prepublication inspection
removes the newly created private staging directory, leaving the intended
destination absent and original input data untouched. The additional identity
checks minimize TOCTOU risk but cannot protect against every concurrent
filesystem mutation; the original security/source-owner approvals remain
mandatory.

**Scope:** this is reproducibility and byte-integrity of offline *software*,
not a validated fixture run, trusted upstream attestation, authenticated
evidence store, verified retest, consent or live deployment. It never invokes
the lab scanner, changes tenant grants or dispatches remediation.

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


## Central native PRIVATE operator launcher

Instead of composing the individual original scripts by hand, start the
[offline PRIVATE HUMAN desk](private_desk.py) **locally**, in a private terminal:

    python3 remediation-integrated-workspace/private_desk.py list
    python3 remediation-integrated-workspace/private_desk.py menu

For scripts or manual repeatability, the same fixed original-native operations
have non-interactive subcommands:

    python3 remediation-integrated-workspace/private_desk.py owner --input-dir /absolute/private/ledger --output-dir /absolute/private/new-owner-workroom
    python3 remediation-integrated-workspace/private_desk.py archives --archive /absolute/private/original.luhz --output-dir /absolute/private/new-recipient-review
    python3 remediation-integrated-workspace/private_desk.py review --cockpit /absolute/private/original-source-free-cockpit --output-dir /absolute/private/new-single-review
    python3 remediation-integrated-workspace/private_desk.py pack-review --cockpit /absolute/private/original-source-free-cockpit --journal-vault /absolute/private/encrypted.luhj --output-file /absolute/private/new-review.luhp

The launcher delegates via the current Python interpreter directly to a
**fixed allowlist** of original native software modules (no shell, no arbitrary
executable, no added network service). It supports original owner intake,
1–12 original source-free recipients/archives, a single source moment,
source-bound HUMAN journals and encrypted continuity, and software-only
installation or local inspection. Interactive selections require a private
TTY, one deliberate YES before execution, and **never ask for secret
passphrases**: native existing vault commands handle these independently.
Original input byte/identity and owner-only private destination requirements
are all enforced by the original native receiving modules. Missing or changed
inputs HOLD, never silently generate synthetic cohorts or claim an approved fix.
The output of every native tool remains REVIEW_ONLY or HOLD, not approval.

The software-only installer/receiver now carry this launcher's exact bytes;
previous portable ZIP editions are NOT compatible with the new software
inventory and should not be silently relabelled. Source hashes are unsigned.
No actual client/operator permission, original producer identity, #177/#182/
#829 closure, source-owner/security/privacy review, mandatory CI or HUMAN GO
is implied. No main merge, deploy, scan, native Apply, verified fix or retest.


### One-operation original-owner desk + prepared source-free archive

Use `private_desk.py owner-package --input-dir /absolute/private/ledger
--output-dir /absolute/private/new-owner-review --output-file
/absolute/private/new-unsent-handoff.luhz` to run original
`workflow.owner_start` followed by a separate original
`portable_cockpit.pack` admission. The original PRIVATE owner directory
is **never packaged or disclosed**. The unsigned/unencrypted source-free
archive MUST be separate from the original directory; it is only prepared,
never automatically sent. Real recipient disclosure permission remains
external. The first private owner workroom may remain if the second stage
fails, with no implied delivery or security approval.


### Preferred encrypted original-owner to PRIVATE recipient handoff

The native launcher can now prepare an owner workroom plus encrypted
original-admitted **source-free** Cockpit in one explicit operator action,
without creating any unencrypted portable ZIP:

    python3 remediation-integrated-workspace/private_desk.py owner-encrypted --input-dir /absolute/private/original-ledger --output-dir /absolute/private/new-original-owner-workroom --output-file /absolute/private/new-encrypted-human-handoff.luhx

This reuses unchanged original `workflow.owner_start` and unchanged
`encrypted_cockpit.encrypt`, including independent original source
re-admission, private 0600 no-overwrite publication, original purpose-bound
AES-GCM cryptography and password confirmation. The optional cryptography
dependency and PRIVATE interactive TTY are checked **before** creating the
original owner workroom. The complete original owner workspace never leaves
its source directory; only selected source-free original native output is
encrypted in memory. A successful encrypted file does NOT authenticate
the source owner/recipient, grant permission, allow release, prove fixed
findings or revoke an older file. Nothing is automatically transmitted.
Native failure after owner creation may leave the original private workroom.
Keep passwords separate, and obtain genuine external disclosure permission
before transfer. DRAFT/HOLD and all original release gates remain unchanged.

## PRIVATE offline browser operatorstudio

Once the native software-only suite is installed, open operator.html. Its
launcher index.html also links to this entirely local operatorstudio. It
provides grouped HUMAN-only original workflow navigation, searchable native
actions, path fields, repeatable ORIGINAL packet inputs, command previews,
and local clipboard copy with a manual fallback. No browser command is run,
no source or HUMAN journal is read, and nothing is uploaded or stored.
Only operators who separately check the originals and their genuine authority
should paste commands into an authorized private Linux terminal.

The native software-only installer and receiver now carry operator_console.py,
operator_ui.js and operator_ui.css with byte-exact pinned source inventory.
The HTML output is generated directly from the current native
private_desk.OPERATIONS metadata. Inline browser script and CSS are protected
with byte-exact CSP hashes, with no network, storage, active targets or
unapproved resource access. The receiver and installed manifest inspector
reject missing/modified operator UI bytes and altered generated operator.html.

This is a strictly HUMAN-only browser preparation experience. It cannot
authorize a grant, scan, retest, approve disclosure, authenticate source owners,
verify a fix, prove current client/operator consent or bypass DRAFT/HOLD.
Operator-supplied paths may be sensitive even when copied locally; clear
local clipboard history after use. Original hosted and permanent VPS CI,
source-owner and independent security/privacy/browser/crypto review,
#177/#182/#829, real independent current client/operator consent with at-use
revocation and explicit HUMAN GO remain mandatory before any release.


### Safe original evidence location and unmistakable transfer file types

Both composed original-owner handoffs now refuse to start if the new portable
output would be written **inside or over an original PRIVATE ledger/bundle
input** (or overlap its path). They also require the exact deliberate
transfer suffix: owner-package makes an unencrypted/unsigned .luhz;
owner-encrypted makes an encrypted .luhx. This source/output separation
and naming gate runs *before* original owner workroom publication, so a
misplaced output cannot pollute or alter the original evidence directory.
The offline operatorstudio mirrors these warnings, but the native Python
path checks remain authoritative. Original native source read/ownership/
link, package admission, private output and cryptographic validators remain
unchanged. Files are never sent by either command.

### Guided offline original-owner to recipient HUMAN journey

The offline operatorstudio now has a three-stage guide on the same static page:
original evidence owner produces a source-free AES-GCM handoff; a separately
approved and physically independent recipient can open the genuinely received
encrypted .luhx with the original archive_workflow; and a HUMAN operator can
seal actually authored original source-bound follow-up journal notes. Each
button only selects the exact corresponding native command form, with fresh
blank paths and no cross-machine state, network, target access or transfer.
No source identity, real consent, signed evidence, fix or verified retest is
inferred from completing those local HUMAN steps.

The two composed owner packet commands now also preflight the distinct
transfer destination before creating the original private workroom. An
already-existing packet path, symlinked output parent or non-owner-private
destination HOLDs immediately, instead of first producing a private original
workroom that cannot be safely paired with its recipient packet. The unchanged
native owner, recipient and encryption validators remain authoritative.


### Directly openable browser product — without a software install

A **generated standalone operator.html** is committed alongside the source
renderer, so an authorized user can copy this one source-only HTML file into
a trusted offline local environment and open it directly. The HTML embeds
the exact-current bounded action inventory, CSP-hashed script and stylesheet.
No client data, original evidence, HUMAN notes, passphrase, private identifier,
credential or target is included. No server, setup, scanner, login, file
upload, browser cache persistence, command execution, grant or external
authorization is provided. The user can prepare but must separately execute
any chosen native operation only where the matching original pinned Python
software exists and current external consent is genuinely established.

The portable native suite installer still regenerates and rechecks its own
operator.html from exact accompanying native Python/JS/CSS, rather than
trusting an HTML artifact received without its original source-lock.
The standalone file can be opened for UI use independently, but it does not
authenticate a source or replace the mandatory hosted/VPS CI and independent
security/privacy/browser/crypto approvals.

## Offline source-free byte-fingerprint desk (unsigned)

The integrated browser operatorstudio and the standalone operator.html now
include a PRIVATE **local WebCrypto SHA-256 byte comparison** for actually
selected source-free .luhx/.luhz/.luhp handoff packets. This does not open ZIP
members, interpret source claims, read client records into a report, invoke
Python, contact a URL, or store files in browser storage. Up to eight files,
20 MiB each and 64 MiB combined are read in-memory only. The browser shows
generic local slot ordinals, exact byte lengths and exact SHA-256. When two
packets are selected it explicitly reports matching/differing bytes; for
multiple packets it reports only distinct local byte identities, NEVER
independent original owners, real chronology or authenticated cohorts.

Operators may *separately confirm* before downloading an optional PRIVATE
unsigned JSON receipt with only ordinals, original byte lengths, SHA-256
and explicit literal false authorization/consent/remediation flags.
Original file names and raw bytes are NEVER written into the receipt.
Digests can still be identifying or linkable: treat the receipt as sensitive,
store it owner-private and never transfer it without genuine independent
authorization. Clearing the workroom drops the results and file picker.
A private browser with WebCrypto unavailable HOLDs, with no noncryptographic
fallback or upload.

These are unkeyed self-consistency fingerprints, **not** signatures,
authenticity checks, valid source/tenant admission, compliance clearance,
security fixes or user/operator permission. Original native validators,
exact-head hosted/named VPS CI, independent privacy/security/crypto/browser
reviews, existing #177/#182/#829, authenticated separate action-time
revocable consent and explicit HUMAN GO remain mandatory.

### Native offline source-free packet fingerprint and counterpart comparison

The same software-only distribution now includes packet_fingerprint.py, a
fully native and private **original source-free packet byte desk**. Its
commands are also in the offline private_desk menu and generated browser
operatorstudio. This gives a practical source-owner/recipient counterpart
for the browser's optional PRIVATE unsigned receipt, without another
service, browser login, dependency, source modification, scanner or tests:

    python3 remediation-integrated-workspace/private_desk.py fingerprint-create --packet /absolute/private/original-packet.luhx --output-file /absolute/private/NEW-unsigned-fingerprints.json
    python3 remediation-integrated-workspace/private_desk.py fingerprint-compare --packet /absolute/private/received-packet.luhx --receipt /absolute/private/separately-authorized-unsigned-fingerprints.json

Repeat --packet for up to 8 original packets **in the same explicit HUMAN
order**. The original packet filenames and content bytes are not included
in the receipt. Bytes are read as fixed-size chunks with O_NOFOLLOW and
exact owner-only PRIVATE 0700 directory / 0600 regular-file guards; per-file
metadata and size stability are rechecked before printing. Receipt creation
uses the existing native atomic no-overwrite 0600 publisher. Both native
and browser receipts carry the same exact bounded, literal false-authority,
slot / byte-size / lowercase SHA-256 schema. Native comparison accepts only
the complete expected schema with no duplicate-key JSON, unexpected flags
or mismatched slot membership, and returns HOLD if any actual received
packet bytes differ. No client identifiers, true sender authentication,
factual source evidence or original contents are ever put into the receipt.

**Security/handling:** these are UNSIGNED/UNKEYED byte fingerprints; an
attacker replacing both packets and receipts can forge a matching receipt.
Reusing a digest does not prove a second reviewer, real time, original client,
permission, independent provenance or a verified security fix. Keep even
source-free digests private; share only after actual external disclosure
approval. The native SHA comparator does not decrypt/read ZIP members, and
never substitutes for the unchanged original native source admission,
cryptography, owner/security/privacy/browser review, consent/revocation and
explicit HUMAN GO. REVIEW_ONLY is not a release signal.

### Cross-device HUMAN fingerprint lookup inside the offline browser

An independently disclosed, source-owner-declared SHA-256 can now be pasted
into the source-free packet workroom alongside an optional exact byte length.
After local WebCrypto hashing, the page identifies the matching LOCAL ordinal
or explicitly HOLDS when no locally selected packet matches. This supports
comparing actual original/received packet bytes on different authorized
machines without uploading the original packet, reading ZIP members, saving
full original file paths in a receipt, or automatically importing any
untrusted JSON receipt. Only canonical 64-character lowercase hex SHA-256 and
bounded exact decimal byte lengths are accepted. The typed comparison is
ephemeral browser memory and never approves a recipient, identity, consent,
fix, release or transfer. Native packet_fingerprint.py compare remains the
strict owner-private source-bound receipt comparison counterpart.

### Optional complete PRIVATE source-free byte-comparison report

When authentic original and received packet files are available to their
separately authorized operator, the native comparison can now atomically
publish a **new private scriptless human-readable HTML plus minimal JSON**
without including original packet bytes, file paths or client evidence:

    python3 remediation-integrated-workspace/private_desk.py fingerprint-compare --packet /absolute/private/received.luhx --receipt /absolute/private/authorized-original-unsigned-fingerprints.json --output-dir /absolute/private/NEW-byte-review

Only when **every exact source-declared slot length AND SHA-256 matches**
does the existing private 0700/0600 original native publisher create the
new report. This report is HTML with CSP preventing script/network,
per-slot digest and byte length, and a SHA-256 of the exact ORIGINAL
unsigned receipt bytes. It is private, linkable and NOT a signature.
Any mismatch is HOLD without a report. Neither successful comparison nor
its report authenticates a client, source owner, separate recipient,
actual permission, chronology, current scope, verified remediation or
security release. The original ZIP/envelope admission remains a separate
mandatory native step. Existing held original CI/review/consent/HUMAN GO
requirements are unchanged.

### Native receive + optional byte-custody check before decrypt

The existing archives operation and original archive_workflow.py now accept
an optional separately authorized PRIVATE UNSIGNED --receipt input:

    python3 remediation-integrated-workspace/private_desk.py archives --encrypted-archive /absolute/private/received-01.luhx --receipt /absolute/private/original-unsigned-fingerprints.json --output-dir /absolute/private/NEW-sourcefree-human-review

Before decryption or original native HUMAN review publication, actual
received packet byte lengths and SHA-256 must match the same ordered slots
of the original separately supplied receipt. Original receipt bytes and
schema are checked before and immediately prior to exclusive publication.
Original source-free ZIP/envelope admission, original authority guardrails,
private destination ownership and native decryption all remain unchanged.
This is OPTIONAL byte consistency, not a newly imposed consent/release gate.
Without --receipt, original 1-12 native packet workflow is unchanged; with
it, comparison is bounded by the native 1-8 receipt contract. A matching
unsigned hash is NEVER real sender/client identity, permission, verified
remediation, a grant, active target authorization or HUMAN GO.

### Single-action original-owner encrypted transfer + separate unsigned receipt

The existing private_desk and offline operatorstudio now offer
owner-encrypted-receipt as a full PRIVATE original-owner product flow:

    python3 remediation-integrated-workspace/private_desk.py owner-encrypted-receipt --input-dir /absolute/private/original-ledger --output-dir /absolute/private/NEW-owner-workroom --output-file /absolute/private/NEW-sourcefree-packet.luhx --receipt-file /absolute/private/NEW-unsigned-byte-receipt.json

The original native source owner admission and original source-free recipient
Cockpit are reused as-is. The native cryptography/passphrase prompt encrypts
only the source-free Cockpit to NEW .luhx; there is no plaintext ZIP step.
After encryption, the original PRIVATE native fingerprint reader publishes
an independent 0600 UNSIGNED receipt containing only exact ciphertext bytes,
ordinal 1, byte length, SHA-256 and literal false authority fields. Neither
product is sent or approved automatically. The two independent output parents
must be owner-private, literal and existing, and original client evidence
is never a permitted output destination. NEW packet and receipt paths are
preflighted before original workroom publication. If later original source
admission, encryption or byte receipt publication fails, earlier PRIVATE
output may still remain and must be handled manually; no unsupported rollback
or automatic disclosure is claimed.

A recipient who has genuinely received both after external authorization can
use the existing optional archives --receipt operation: source-free actual
ciphertext bytes are compared BEFORE original decryption, and the original
native source-free admission and HUMAN recipient workroom retain all their
separate checks. A fingerprint is NOT a signature or authenticated sender,
client consent, valid assessment scope, remediated finding or HUMAN GO.

### Clearer native/browser operator paths for actual source-free packets

The original native archives action admits exactly one original transport
mode: genuinely received .luhz OR .luhx, never both. The integrated native
operator menu and the offline browser now clearly surface this existing
native requirement before a private command is prepared. Private native
fingerprint commands show the original 1–8 distinct-packet bound; the
browser file-picker now refuses arbitrary ZIP, JSON or original client files
instead of merely relying on an HTML accept suggestion. This does not grant
permission to open any packet or prove that a renamed packet is source-free:
original native recipient admission and separate genuine disclosure approval
remain required. The complete offline owner encrypted + unsigned receipt,
recipient original byte match before decrypt, and original HUMAN review flow
remain separately operated and offline.

## Complete scriptless offline suite start page

The complete software-only installer now opens with a redesigned, fully
responsive PRIVATE landing page generated by landing.py and published as
index.html. The local landing page groups the ORIGINAL source-pinned
Casework, Artifact Ledger, HUMAN Portfolio, and encrypted HUMAN handoff
modules with the unified operatorstudio as the primary working entry point.
It walks the operator through ORIGINAL OWNER, independently approved PRIVATE
RECIPIENT byte comparison, and real HUMAN follow-up. Each module link stays
relative to its installed local suite; no server, script, network, cookie,
tracking, API, grant, scanner or access to source records is added.

An exact standalone scriptless start.html is also committed in this own
integration directory for direct opening from an offline browser. The
original installer regenerates its own index.html from landing.py, and the
existing native verify + strict second-device receiver require that exact
version of the bundled landing renderer. The generated standalone entry
page and installed start page are software/UI only: linked original modules
require the complete, separately installed, pinned PRIVATE suite to exist.
No release/authorization decision, CI bypass or original source-owner code
change is implied by this delivery.

### Context-aware local links, without external dependencies

The standalone start.html lives in the checked-out integration source
folder and uses repo-relative links to original modules one directory up;
the embedded operator.html remains in the same folder. The installed
software-only suite publishes the same scriptless landing through its
root-level index.html and uses installed-suite-relative links instead.
Both layouts retain an exact local native user guide link; neither attempts
remote fallback or silently assumes source checkout has been installed.
Original native installed-software receiver always compares its root
index.html against the exact locally bundled default rendering.
