# LightUp PRIVATE lab disclosure preflight

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Independent add-only operator companion, not a scanner, grant, source authenticator, security verdict or release.

## Actual product

preflight.py takes 1–12 already-produced owner-PRIVATE original isolated-lab JSON artifacts and calls the *original* lightup.lab_inspect.inspect_artifact() validator. Unsupported input or a missing original module produces HOLD. The companion copies only explicitly bounded, allowlisted, aggregate fields from the original inspector: no target address, original path/filename, run/scenario ID, finding title, evidence text, model response, credentials or source objects enter the outputs.

In an **existing owner-owned 0700 PRIVATE directory** it creates these files, without overwrites:

- PRIVATE-review.html: scriptless, printable PRIVATE original-declaration review with source-ordinal, counts, evidence-ref coverage and explicit HOLD/authority warning. Offline CSP denies all network connections.
- PRIVATE-receipt.json: machine-readable PRIVATE source-free per-ordinal declarations, with source_byte_bound=false, all authority flags false, no hashes or original content.
- PRIVATE-counts.csv: an independent small-cohort-suppressed count handoff. For fewer than five source files even the source count is suppressed. With larger cohorts, every nonempty artifact kind needs at least five entries or the entire kind breakdown is suppressed. This is NOT proof of anonymity; distribution remains a HUMAN decision.

Input is admitted by the original lab inspector as bounded non-symlink local JSON. Output files are exclusive 0600; ordinary writing failures clean up new outputs. Nothing uploads, executes a model, scans, grants, or contacts a network.

## Usage (offline only)

The original inspector lives on held original source-owner [PR #1610](https://github.com/Zennay/Lightup/pull/1610), reference db1b81f359a42274d7cfe00a811e9539649ded62, **not yet on main**. Use an environment where genuine reviewed original owner source is installed. The companion does not vendor or alter it. Imported code is not itself cryptographic provenance. Without it, the workflow fails closed.

~~~sh
mkdir -m 700 ./private-disclosure-desk
python3 assessment-disclosure-preflight/preflight.py \
  ./private/assessment-01.json ./private/assessment-02.json \
  --private-output-dir ./private-disclosure-desk
~~~

Exit **2 = REVIEW_ONLY** after files are privately produced. Exit **3 = HOLD** and no approval; exit 0 is never a release signal. Minimum source cohort defaults to five and can only be raised via --minimum-cohort (up to twelve).

## HUMAN disclosure checklist

Before any external handoff, check the genuine origin of each private source, current client/operator rights and action-time revocation, confidentiality/retention conditions, whether aggregated counts could re-identify a customer or laboratory, and the intended recipient. A source ordinal is *not* a durable identifier. The receipt is **not byte bound or signed**, and identical aggregates can arise from different source bytes. The PRIVATE CSV is not by definition anonymous or safe to publish. Unverified findings remain unverified.

**Release fence:** the parent LightUp project remains Incubate / M3-M7 PLAN/LAB ONLY DRAFT/HOLD. No main merge or deploy, active target, grant, deletion, retest or client authority. Original exact-head GitHub hosted and permanent named VPS CI, original source owner and independent security/privacy/browser review, #177/#182/#829, separately authenticated current client/operator permission with at-use revocation, and explicit HUMAN GO are still required. No QA suites, CI workflow, scanner, runtime, authorization or other workers' files are modified.


## Second product: exact-receipt HUMAN follow-up (offline)

A second, independent read-only companion **human_review.py** supports a real PRIVATE operator decision flow without touching any original lab data, original source owner, grant, or client:

1. Prepare an exclusive 0600 PRIVATE-human-template.csv from the already-generated PRIVATE-receipt.json. Every row carries the **full SHA-256 of the exact receipt file bytes**, its original one-based ordinal and fixed kind; all notes begin empty.
2. A human manually records one permitted *non-authorizing* stage per ordinal (unreviewed, privacy_hold, source_owner_hold, consent_hold, follow_up_required, human_reviewed_no_release), a bounded question and a bounded next action.
3. Reopen that exact completed CSV together with the exact PRIVATE receipt. The importer rejects changed receipt bytes, missing/duplicate/extra ordinals, reordered rows, modified kind, altered digest, unknown stages, unexpected columns, oversized/control-bearing HUMAN text and malformed CSV **before** publishing anything. It then writes a new 0600 scriptless offline PRIVATE-human-followup.html report into an existing 0700 PRIVATE directory, exclusive and non-overwriting.

~~~sh
# From a trusted offline workstation; never put actual client files in git.
python3 assessment-disclosure-preflight/human_review.py prepare \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --private-output-dir ./private-disclosure-desk
# Manually fill the CSV locally. No real authority may be written into its stages.
python3 assessment-disclosure-preflight/human_review.py render \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --answers ./private-disclosure-desk/PRIVATE-human-template.csv \
  --private-output-dir ./private-disclosure-desk
~~~

The CSV is **PRIVATE**, not a public anonymized report. It can contain confidential HUMAN questions or actions, and even a reviewed HUMAN stage **never** becomes an authorization, approved release, verified finding, grant, consent or successful remediation. Its SHA binds solely to the unsigned aggregate receipt's bytes — **never** to the original sensitive lab source, human sender identity or a real signing key. Wrong receipts HOLD without silently copying decisions. Both commands return REVIEW_ONLY exit code 2 or HOLD exit code 3; no automatic sharing, target interaction or release.


## Third product: PRIVATE browser editor (no spreadsheet required)

Open review-studio.html from a trusted offline browser with review-studio.js and review-studio.css in **the same directory**. Use modern browser WebCrypto in a secure local file context. The browser has a strict CSP with no connections, models, remote assets, storage or tracking. This source-only local three-file workspace is intentionally not a hosted app or merged product release. Where an offline browser cannot grant WebCrypto to local files it will HOLD; do not disable browser security protections.

- Load PRIVATE-receipt.json and PRIVATE-human-template.csv together. Browser computes the exact full SHA-256 of the actual receipt bytes and admits a bounded receipt schema, all literal-false authority flags, all ordinals and allowed kinds and stages. Invalid files HOLD without replacing existing unsaved in-memory edits.
- Filter/search all source-free review records, edit only HUMAN stage/question/next action, receive an unsaved-edit warning, and export a complete PRIVATE CSV in original ordinal order. Both browser and native importer refuse unknown stages, overlong/control-bearing HUMAN notes and risky spreadsheet formula prefixes.
- Exported PRIVATE-human-reviewed.csv can be used instead of the completed template with the original native human_review.py render command. That CLI remains the stricter authoritative source-free receipt/CSV re-admission path.
- No original assessment source artifact, target, evidence, scan, model, grant, reviewer authentication or signed provenance enters the studio. The user can type sensitive things into HUMAN notes: the output must remain PRIVATE. Local browser SHA covers only the source-free receipt, **not original PRIVATE lab artifact bytes**.

This makes the entire workflow usable with a local visual HUMAN editing desk, but does **not** remove the mandatory original source-owner dependency, verified authorization and held release controls. Browser-side JSON does not independently detect duplicate JSON keys; the native report builder remains responsible for canonical CSV/receipt validation, and even that never grants release authority.


## Encrypted PRIVATE HUMAN continuity (.luhd) and revision comparison

The local browser now includes **review-vault.js**, a binary, purpose-separated HUMAN packet format LUHUM001. Its authenticated 68-byte header contains eight-byte purpose/version magic, fresh 16-byte PBKDF2 salt, fresh 12-byte AES-GCM nonce and raw 32-byte SHA-256 of the **exact PRIVATE receipt bytes**. The entire header is authenticated AES-GCM additional data. AES-256-GCM encrypts the already-admitted source-free HUMAN CSV under PBKDF2-SHA256 (600,000 iterations); max plaintext 256 KiB, min passphrase length 14, max 256. Every export uses fresh randomness. There is no automatic network or browser persistence.

When reopening, the browser requires the exact PRIVATE receipt, either a plaintext CSV *or* encrypted .luhd and the corresponding passphrase. It checks the header and exact receipt digest before authenticated decryption, then runs the **same complete original ordinal/kind/stage/field CSV intake** on decrypted notes. Incorrect receipt, password or ciphertext → HOLD, with previous in-memory HUMAN edits preserved. Clear-text export still exists but requires an explicit privacy warning. Password inputs are cleared after use; this is not a secure memory-erasure claim. No password recovery.

### Visual read-only HUMAN revision comparison

After opening the current source-free HUMAN review, select an older encrypted .luhd and its separate password. The workroom decrypts into memory, re-admits it against the same exact receipt and displays changes in stage, question and next action. Prior notes are **read-only** and never copied into the current HUMAN choices. Literal matching never establishes authentic independent reviewer agreement, consent, original source provenance or verified remediation.

### Native offline encrypted HUMAN report

The native human_review.py render command accepts **either** --answers for a plaintext PRIVATE HUMAN CSV, **or** --vault for an encrypted PRIVATE HUMAN .luhd. The latter asks for a passphrase from an interactive non-echoed terminal, decrypts with the optional Python cryptography package, and immediately uses the same receipt-exact native CSV admissibility checks. No decrypted CSV intermediary is saved to disk; the **resulting PRIVATE scriptless HTML does include decrypted HUMAN notes**, so it must stay private until separately reviewed for legitimate recipient disclosure.

Use a trusted offline system:

~~~sh
python3 -m pip install -r assessment-disclosure-preflight/requirements-native.txt
mkdir -m 700 ./another-private-review
python3 assessment-disclosure-preflight/human_review.py render \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --vault ./private-disclosure-desk/PRIVATE-human-reviewed.luhd \
  --private-output-dir ./another-private-review
~~~

New private output filenames are exclusive and non-overwriting; previous HUMAN reports stay untouched. Opening and re-exporting under a **new** password performs memory-only re-encryption using new salt/nonce, without writing a plaintext export. Passwords, original lab source files and recipient authorization must be handled separately. The receipt hash binds to **unsigned count-only receipt bytes**, not the original source, tenant, owner, consenting actors or legal authority. Neither an encrypted file nor a HUMAN reviewed label is a signed, approved or source-authenticated assessment.

**Release stays INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD**: original exact-head hosted and permanently registered VPS CI, original source owner, independent security/privacy/browser/crypto review, original #177/#182/#829, genuinely authenticated current separate client/operator consent including action-time revocation and explicit HUMAN GO remain mandatory. No QA/regression suites, scanner, grant, target interaction, merge or deployment have been added.


## Source-free HUMAN-only aggregate handoff, without note text

The existing native HUMAN CLI now also supports **summarize** against an exact existing PRIVATE receipt plus either a PRIVATE HUMAN CSV or an encrypted .luhd (non-echoed passphrase). It emits exclusively new owner-only 0600 **PRIVATE-human-summary.csv** with no human questions, next-action text, target, origin, evidence or source digest. If fewer than five records are present, source count is hidden. For five or more, the count of any rare nonzero HUMAN stage (<5) suppresses the **entire** stage breakdown rather than disclosing a potentially identifying rare category. The minimum threshold can be raised to 6–12 but cannot be lowered below five. Status remains REVIEW_ONLY with explicitly false origin/consent/release declarations and never confers approval.

~~~sh
mkdir -m 700 ./another-private-counts
python3 assessment-disclosure-preflight/human_review.py summarize \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --vault ./private-disclosure-desk/PRIVATE-human-reviewed.luhd \
  --minimum-cohort 5 \
  --private-output-dir ./another-private-counts
~~~

The visual browser workspace also offers **Export suppressed PRIVATE HUMAN counts only**, using the same stage/category suppression logic and requiring a separate explicit confidentiality confirmation. Neither aggregate is automatically anonymous, a client deliverable, an approved report, consent, a grant or source-authenticated data. They are strictly PRIVATE HUMAN planning materials.


## Complete native bidirectional encrypted HUMAN workflow (without a browser)

Native human_review.py now also has **seal**. It first re-admits the exact full PRIVATE receipt and every plaintext source-free HUMAN ordinal/type/stage/note, requests a new password twice through a non-echoed interactive TTY, then encrypts the *same unchanged source-free CSV bytes* in memory using the exact same LUHUM001 / PBKDF2-SHA256 600k / AES-256-GCM header+AAD format as the browser. The resulting PRIVATE-human-reviewed.luhd is an exclusive new owner-only 0600 file, with complete ciphertext staging before final publication. No decrypted or extra plaintext CSV staging is created. Existing original source files and source-owner validation are not altered.

~~~sh
mkdir -m 700 ./another-private-sealed
python3 assessment-disclosure-preflight/human_review.py seal \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --answers ./private-disclosure-desk/PRIVATE-human-template.csv \
  --private-output-dir ./another-private-sealed
~~~

Later the original browser may open that .luhd file against precisely the same original receipt bytes, or the native render/summarize commands may decrypt it with the non-echoed password. Passphrases do not authenticate the original producer, reviewer, owner, client or consent. Required optional dependency and HOLD handling are the same as for native decryption. Incorrect source, invalid CSV, password mismatch or missing TTY aborts without publishing new final ciphertext.

Native and browser generate newly salted ciphertext for each deliberate export; neither changes the original receipt, creates an assessment, contacts a target, grants scope nor signals release readiness.


## Private output directory binding

Both original aggregate preflight and the HUMAN native publisher now open the output directory once with non-following directory flags, verify owner and group/other access on that **open descriptor**, then stage, fsync, hard-link exclusive final output names, roll back ordinary publication failures, and clean private staged files using descriptor-relative operations on that same directory inode. No path re-resolution is needed between permission check and publishing. Individual final filenames are atomic and never overwrite existing files/symlinks; the full three-file preflight set is **not** a single atomic transaction for readers observing it mid-publication. Interrupted processes may leave owner-only staging files that require private cleanup. This does not imply independent security certification.


## Ready-to-open standalone PRIVATE HUMAN studio (no local server)

The complete production-source browser workroom is committed as [standalone.html](./standalone.html). Open that **single HTML file** locally in a modern offline browser with Web Crypto support. Its HTML includes the real editor, encrypted HUMAN vault handling, local revision comparison, original PRIVATE receipt admission and counts-only export. All styles and scripts are embedded with **three exact SHA-256 Content Security Policy pins** instead of permissive inline scripts. Its CSP denies any outgoing connection, frames, external media, third-party sources, object embedding or form submission. It needs no package manager, cloud server, cookies, web storage, original client files embedded in the artifact, or scan/target/model access.

To regenerate after changing one of the four original static source files, use the stdlib Python 3 builder package.py from the trusted source checkout. It reads only bounded regular no-follow files in this directory, refuses changed/missing original HTML/CSP anchors, computes cryptographic hashes of the exact inline source bytes and exclusively publishes a complete new file. The default output is standalone.html; **it will never overwrite an existing file**. For a deliberate replacement build, specify a fresh basename, review that new asset, and replace the tracked standalone through the normal owned PR workflow. Never pass a client/assessment file to the build process. The standalone itself contains only product code, not private customer data.

The original multi-file review-studio.html and adjacent CSS/JS remain usable as source form. The standalone has the same PRIVATE receiver/export behavior, including unchanged HOLD on all release/authorization conditions. Browser receipt JSON import now rejects duplicate object property names (including escaped key spelling) in every object before parsing and carrying HUMAN notes. Original native receipt byte admission remains the stricter authority-free offline path; the browser is not a trusted source authenticator or independent privacy/crypto certification.


## Browser-only printable PRIVATE HUMAN follow-up report

The visual workroom and the actual standalone HTML now offer **Export printable PRIVATE HUMAN report**. It produces a complete, local, scriptless HTML containing only the source-free receipt's ordinal/kind and *human-entered* stage, question and next action. It includes a category breakdown and clear source-provenance/authorization warnings, has no scripts, remote resources, targets, original evidence payloads or full receipt hash, and uses HTML-escaped values rather than interpreting HUMAN text as markup. This is the pure-browser equivalent of the native read-only HUMAN report, useful for recipient preparation when Python is not installed.

Unlike the small-cohort-suppressed category CSV, the printable HUMAN report is deliberately **not anonymous** and includes PRIVATE free text; browser downloads can sync to cloud storage. Therefore its export requires an explicit human privacy confirmation. The operator must separately review confidentiality, recipient identity and current client/operator permissions before any handoff. Browser-side acceptance remains an unsigned receipt/CSV check, not authentic source proof. For strict native original byte admission and 0600 owner-only file publishing, use the Python workflow instead.


## Complete one-file encrypted PRIVATE HUMAN handoff — LUHBP001 (.luhb)

The local browser and native HUMAN CLI now support one encrypted packet containing **both** the exact original **unsigned source-free preflight receipt** and the previously admitted PRIVATE HUMAN CSV. Recipients no longer need to separately preserve/locate the receipt. This never includes raw original lab results, targets, evidence bytes, models, authorization grants or original client documents. The packet is entirely password-encrypted, including its receipt metadata.

### Native offline sender

From a trusted offline terminal, with an existing owner-only 0700 output folder and installed optional cryptography dependency:

~~~sh
python3 assessment-disclosure-preflight/human_review.py seal-bundle \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --answers ./private-disclosure-desk/PRIVATE-human-reviewed.csv \
  --private-output-dir ./another-private-handoff
~~~

The CLI first fully re-admits exact receipt+CSV identities, prompts twice for a new password on a non-echoed TTY, then publishes exactly one new 0600 PRIVATE-human-handoff.luhb in the existing private directory; it never overwrites existing files or writes an additional plaintext staging file.

### Native offline recipient

~~~sh
python3 assessment-disclosure-preflight/human_review.py render \
  --bundle ./another-private-handoff/PRIVATE-human-handoff.luhb \
  --private-output-dir ./recipient-private-report
python3 assessment-disclosure-preflight/human_review.py summarize \
  --bundle ./another-private-handoff/PRIVATE-human-handoff.luhb \
  --private-output-dir ./recipient-private-counts
~~~

Create each output directory beforehand with owner-only 0700 permission. The receipt is inside the encrypted package. Passing a second --receipt with --bundle is refused. Receipt bytes and HUMAN text are decrypted in memory, then independently readmitted by the original local receipt+CSV validators; no plaintext CSV is published en route. PRIVATE report HTML still contains HUMAN notes, while the separately generated counts-only CSV remains small-cohort-suppressed. These are human declarations, not release approvals.

### Browser sender / recipient

Load an original receipt with a matching HUMAN CSV or encrypted .luhd, edit locally, choose **Export complete encrypted PRIVATE HUMAN handoff (.luhb)**, and enter/confirm a new password. The receiving workroom instead selects only the .luhb and password; no second receipt needed. This is supported in the original multi-file browser and the source-bundled standalone. Earlier two-file .luhd imports/exports remain supported; neither workflow contacts a network or grants permission.

### Binary format and precise trust limit

LUHBP001 is a purpose-separated binary AES-256-GCM packet. Outer 36-byte header: eight-byte LUHBP001 marker, 16 random salt bytes, 12 random nonce bytes; the entire header is authenticated AES-GCM associated data. Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, 256-bit key. Plaintext inside authenticated ciphertext: second LUHBP001 marker, big-endian 32-bit receipt length and CSV length, exact unsigned PRIVATE receipt bytes, exact HUMAN CSV bytes. Each source is strictly bounded to 256 KiB. Password mistakes, tag failure, unsupported version, inconsistent lengths, duplicate receipt keys and noncanonical HUMAN rows all refuse before any current HUMAN review is replaced.

The ciphertext protects against passive disclosure/tampering while its password remains secret. It does NOT prove authentic original lab provenance, review authorship, client/operator consent, current revocation, fixes, approved assessment rights or HUMAN GO. Original receipt and HUMAN CSV are explicitly unsigned. No anonymity, secure memory erasure or password recovery is promised. Source/cryptography/browser CI reviews and action-time authorization/release gates remain mandatory. Keep PRIVATE, DRAFT/HOLD, without production target interaction, automatic transfer, merge or deployment.


### Offline re-encryption / independent recipient passphrase rotation

For an already received original PRIVATE-human-handoff.luhb packet, the native CLI can rotate its passphrase without ever writing an unencrypted receipt or HUMAN CSV to disk. This is not a new scan, authenticated sender signature or release approval; it is a new owner-only encrypted output after full readmission.

~~~sh
mkdir -m 700 ./rekeyed-private-handoff
python3 assessment-disclosure-preflight/human_review.py rekey-bundle \
  --bundle ./another-private-handoff/PRIVATE-human-handoff.luhb \
  --private-output-dir ./rekeyed-private-handoff
~~~

First enter the existing password, then a NEW password twice. The original LUHBP001 packet is decrypted in memory, the exact embedded unsigned receipt and source-free HUMAN CSV are readmitted, a new random salt and nonce are used, and PRIVATE-human-handoff-rekeyed.luhb is published exclusively as a new 0600 file. The original encrypted source file is never overwritten or deleted, and output is never a completed security review. Password change cannot revoke copies distributed earlier with an old password; recipients must handle deletion/revocation using real independent policy and controls. Use a different private output directory for additional revisions.


## Fourth product: source-receipt-bound TWO-reviewer HUMAN reconciliation

The optional native [reconcile.py](reconcile.py) composes TWO independently
completed PRIVATE human assessments of the **same exact unsigned PRIVATE
receipt bytes**. No original lab source, target network, models, scanning,
grant, approval, identity inference or release is involved. This does not
combine distinct source receipts, infer shared source identities from ordinals,
or treat two agreeing reviewer texts as independently verified evidence.

**Prepare**: admit the original receipt with the unchanged strict receipt
parser and each completed CSV with the unchanged native HUMAN validator.
Reviewers can supply the original plaintext .csv, receipt-bound encrypted
.luhd vault, or all-in-one .luhb bundle. Encrypted inputs are decrypted only
in memory using existing interactive non-echo prompts (requires optional
cryptography dependency); bundled receipt bytes must be EXACTLY identical
to the one supplied by --receipt. For each reviewer the **SHA-256 of original
plaintext completed HUMAN CSV bytes** is pinned in every decision row;
ciphertext identity or HUMAN sender identity are NOT inferred.

The operator receives (both owner-only 0600, exclusive/non-overwriting):

- `PRIVATE-reconcile-comparison.html`: local scriptless PRIVATE side-by-side
  stage, question, next-action and disagreement report for every ordinal.
  Contains potentially sensitive HUMAN text. Never distribute as anonymous.
- `PRIVATE-reconcile-decisions.csv`: one explicit choice per source ordinal,
  `HOLD` (default), `A`, or `B`, and an operator-entered human reason.
  All original ordinals/kinds, the original receipt digest and both original
  reviewer CSV digests are pinned. Selecting A or B requires a nonblank HUMAN
  reason; no HUMAN decisions are accepted from unbound/missing/reordered rows.

~~~sh
mkdir -m 700 ./private-review-reconcile
python3 assessment-disclosure-preflight/reconcile.py prepare \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --a-csv ./reviewer-A/PRIVATE-human-reviewed.csv \
  --b-csv ./reviewer-B/PRIVATE-human-reviewed.csv \
  --private-output-dir ./private-review-reconcile
# Inspect PRIVATE-reconcile-comparison.html LOCALLY.
# Edit PRIVATE-reconcile-decisions.csv manually (HOLD / A / B + reason).
python3 assessment-disclosure-preflight/reconcile.py finalize \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --a-csv ./reviewer-A/PRIVATE-human-reviewed.csv \
  --b-csv ./reviewer-B/PRIVATE-human-reviewed.csv \
  --decisions ./private-review-reconcile/PRIVATE-reconcile-decisions.csv \
  --private-output-dir ./private-review-reconcile
~~~

For encrypted reviewer inputs use `--a-vault file.luhd`,
`--b-vault file.luhd`, `--a-bundle file.luhb` or
`--b-bundle file.luhb` instead of the corresponding `--*-csv`.
Each reviewer independently selects exactly ONE format. Do not put
passwords in command arguments; the original decryptor prompts on the
interactive local terminal.

**Finalize** re-opens both original HUMAN submissions and the exact receipt.
Any changed byte, absent reviewer, reordered, duplicated or extra choice,
mismatched SHA-256, altered ordinal/kind, unexpected CSV field, unsupported
selection, unsafe/formula-like reason, or no justification for A/B produces
HOLD (exit 3) without claiming approval. Accepted choices create an original
native-importable `PRIVATE-reconciled-human.csv`, scriptless
`PRIVATE-reconciled-report.html` and independent
`PRIVATE-reconciled-counts.csv` (minimum cohort defaults to five, optional
`--minimum-cohort 5..12`; small/sparse groups are suppressed using the
unchanged native HUMAN counts formatter). This aggregate file contains no
reviewer notes or source identifiers but is **not guaranteed anonymous**; *unselected* rows always reset to
`unreviewed` with empty notes, even if the reviewers agree. No source
finding, consent, evidence or remediation state changes. The resulting
CSV may be opened by the existing `human_review.py render` command for
its unchanged additional admission; it is still PRIVATE and review-only.

Each of the two prepare files and three finalize files is independently atomically
published with existing owner-owned 0700 directory / 0600 file rules.
Pair publication itself is not one filesystem transaction: after an
interrupted later publish, earlier PRIVATE files may remain. Inspect filenames and use
a **fresh PRIVATE output directory** for a new attempt, never weaken custody,
replace a report silently, or treat a partial pair as completion.
A plaintext browser download elsewhere remains exposed until a HUMAN
operator handles it. Source/receipt SHA-256 proves only equality of the
specified bytes, not provenance, authenticated approval, reviewer identity,
original customer consent, or security verification.

**Release remains DRAFT/HOLD.** No changes to the original `lightup.lab_inspect`,
scanner, runtime, scope grants, active targets, CI configuration or QA suites.
Native offline implementation and source syntax checks are not human/security
review or CI acceptance. All original release and consent gates above apply.


### Confidentiality-first alternative: fully encrypted final HUMAN handoff

If the only intended follow-up is to pass the selected HUMAN decisions to a
separately approved recipient, avoid creating the new plaintext reconciled CSV
**and** the scriptless report. Use `--encrypt-result` on `finalize`:

~~~sh
mkdir -m 700 ./private-review-sealed-output
python3 assessment-disclosure-preflight/reconcile.py finalize \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --a-bundle ./reviewer-A/PRIVATE-human-handoff.luhb \
  --b-bundle ./reviewer-B/PRIVATE-human-handoff.luhb \
  --decisions ./private-review-reconcile/PRIVATE-reconcile-decisions.csv \
  --encrypt-result \
  --private-output-dir ./private-review-sealed-output
~~~

This option uses the unchanged native AES-256-GCM authenticated
`vault_native.encrypt_bundle` with a **new hidden interactive password
and fresh random KDF salt/nonce** to seal the exact original unsigned
receipt bytes plus human-selected reconciled CSV bytes directly from
memory. Two exclusively created 0600 owner-PRIVATE outputs result:
`PRIVATE-reconciled-human.luhb` and
`PRIVATE-reconciled-counts.csv` (source/note-free stage counts with
original small-cohort suppression). Neither a new plaintext completed
CSV nor a plaintext reconciliation report is written by this mode;
the *existing* reviewer input files, decision worksheet, original
receipt, and unencrypted prior files are not erased. Passwords are
not recoverable and cannot authenticate a reviewer or confer consent.

The encrypted output opens with the ORIGINAL local review studio's
receipt+HUMAN `.luhb` import or with the original
`human_review.py render --bundle` after a separately authenticated
local disclosure decision. The operator must still verify the actual
recipient, provenance and consent independently. Unknown/cancelled
passwords, changed receipt/review bytes or privacy/crypto admission
fail closed (HOLD). The encryption does not prove original evidence,
remediation, client permission, live scanning authority or a release.


### Interactive local decision entry (no spreadsheet editing)

The same offline CLI also provides a native trusted-terminal HUMAN decision desk.
After reading the original PRIVATE comparison report, an operator can choose
HOLD/A/B and type a nonblank private reason for each explicitly selected A/B
ordinal. This emits `PRIVATE-reconcile-interactive-decisions.csv` using the
same exact receipt/reviewer-byte digests and same unchanged strict native
finalizer. It asks every ordinal separately; it never silently adopts even
identical reviewers. It is entirely in memory until **every** human choice
is completed, then a single exclusive owner-only 0600 file is published.

~~~sh
mkdir -m 700 ./private-interactive-decisions
python3 assessment-disclosure-preflight/reconcile.py decide \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --a-csv ./reviewer-A/PRIVATE-human-reviewed.csv \
  --b-csv ./reviewer-B/PRIVATE-human-reviewed.csv \
  --private-output-dir ./private-interactive-decisions
# Answer the local HOLD / A / B questions. Q cancels with no new output.
# Then use the EXISTING finalize command but specify:
# --decisions ./private-interactive-decisions/PRIVATE-reconcile-interactive-decisions.csv
~~~

The command **requires interactive stdin and stdout on a trusted terminal**,
rejects redirected/autogenerated selections, and displays only reviewer
stages plus whether their HUMAN notes differ (not their confidential
question/action text) in the terminal. Compare the full sensitive HUMAN text
in the previously generated scriptless PRIVATE HTML before selecting.
Cancellation, invalid selections, unsafe/incomplete reason or missing
terminal -> HOLD, without a partially published decision CSV. This is still
unverified HUMAN work, not a consent or approval authority.


## Fifth product: ready-to-open offline two-reviewer HUMAN browser studio

Open the committed [**one-file PRIVATE reconciliation application**](reconcile-standalone.html)
locally from a trusted workstation (or open [reconcile-studio.html](reconcile-studio.html)
alongside its exact `reconcile-studio.css`, original `review-vault.js` and `reconcile-studio.js` source files).
This is **actual self-contained software already committed** to the same
existing DRAFT/HOLD PR, not an illustration or a future plan.

The browser guides a complete HUMAN-only workflow:

1. Load the existing exact unsigned `PRIVATE-receipt.json` and TWO completed
   independently supplied native HUMAN reviews, up to 12 source-free ordinals.
   Independently select plaintext CSV, original encrypted `.luhd` or
   exact-receipt-containing encrypted `.luhb` for reviewer A and B. The
   existing LightUp WebCrypto PBKDF2-SHA256/AES-256-GCM opens encrypted
   data only in memory and clears both password input fields. A bundle
   must contain the EXACT original receipt bytes, not just a similar digest.
   A strict bounded browser parser refuses nested duplicate JSON keys,
   invalid authority flags, missing/reordered/duplicate source ordinals,
   unsupported source kinds, malformed spreadsheet CSV, changed receipt
   SHA-256, wrong reviewer CSV columns/stages/notes and risky formula prefixes.
   The browser hashes the exact original unsigned receipt bytes and the
   native-completed HUMAN **plaintext CSV bytes of BOTH reviewers** using
   local WebCrypto (not the randomized encrypted ciphertext). An optional
   original UTF-8 BOM is deliberately preserved through decryption so
   the native finalizer sees identical CSV bytes. Different ciphertext
   is not proof of distinct reviewer content or reviewer identity.
2. Compare A/B stages, PRIVATE questions and proposed next actions
   side by side in an accessible responsive interface. Filter literally
   different vs equal HUMAN text, unresolved vs explicitly selected rows, or
   search local note text; filters **never** omit any original ordinal from
   later native handoff.
3. Start with **HOLD on every row**, even identical or same-stage HUMAN
   statements. Explicitly choose A or B per ordinal and provide a bounded
   safe HUMAN justification. Unsafe or missing reasons disable export.
   No automatic agreement, security verdict, actual reviewer identity,
   approval, grant or release is inferred.
4. Export the original native-compatible seven-column
   `PRIVATE-reconcile-browser-decisions.csv`, containing only exact unsigned
   receipt/reviewer **byte SHA-256s**, all original source ordinals and
   declared kinds, HUMAN selections and HUMAN reasons. All original
   reviewer question/action text stays out of this decision CSV unless
   the operator deliberately enters it into the reason.
5. **Resume an earlier decision draft** after loading all three exact
   original files. The browser atomically admits every original hash,
   ordinal, kind, schema column, selection and reason and requires a
   second HUMAN confirmation before replacing the current decisions.
   Mismatched/reordered/changed drafts HOLD without changing current work.

Use the unchanged **native** original finalizer to render or seal the result:

~~~sh
mkdir -m 700 ./private-browser-finalized
python3 assessment-disclosure-preflight/reconcile.py finalize \
  --receipt ./private-disclosure-desk/PRIVATE-receipt.json \
  --a-csv ./reviewer-A/PRIVATE-human-reviewed.csv \
  --b-csv ./reviewer-B/PRIVATE-human-reviewed.csv \
  --decisions ./private-restricted/PRIVATE-reconcile-browser-decisions.csv \
  --encrypt-result \
  --private-output-dir ./private-browser-finalized
~~~

The browser accepts existing native HUMAN CSV, encrypted receipt-bound `.luhd`,
and encrypted complete original receipt+HUMAN `.luhb` **separately for A and B**,
without saving additional plaintext HUMAN reviewer files. The existing native
`reconcile.py prepare/decide/finalize` remains the preferred terminal-only
workflow. Finalizing a browser decision against encrypted original files uses
`--a-vault` / `--a-bundle` and/or `--b-vault` / `--b-bundle` instead of CSV;
both routes digest the identical decrypted original native CSV bytes.
The standalone browser's downloaded decision CSV is confidential and
may initially be in a normal-permission Downloads folder; a HUMAN
operator must move it to a trusted owner-PRIVATE destination before
native use. The offline interface neither modifies nor deletes the
originals or prior browser downloads. No content is sent to a server,
stored in localStorage, or persisted automatically; the app clears
the DOM and file inputs when leaving the page, without promising OS
or browser memory erasure. It works only where `file://` pages have
a secure WebCrypto context; never disable browser security to force it.

**Standalone software custody:** [reconcile_package.py](reconcile_package.py)
rebuilds the exact self-contained HTML with SHA-256-pinned inline CSP
from the THREE original committed source files, rejects unexpected
markup/inventory, reads bounded local regular files without following
symlinks and publishes only a new file. The **already committed**
[reconcile-standalone.html](reconcile-standalone.html) includes the original
pinned native-compatible LightUp browser cryptography source, but no external
imports, fetches, scans, models, credentials, original customer source
or private HUMAN reviews embedded. All standalone code remains
DRAFT/HOLD: it is not merged on main, deployed, independently
security/privacy/browser approved, authenticated, a substitute for
source-owner original `lightup.lab_inspect`, or a security clearance.


### Original PRIVATE input custody is now enforced by the native importer

The existing native `human_review.source_bytes` and the encrypted .luhd/.luhb
`vault_native` readers now check the **actual opened regular file descriptor**
for current user UID, owner-only mode (no group/other bits), exactly one
hardlink, bounded size, no-follow admission, and pre/open/post read
`device/inode/mode/UID/link-count/size/mtime/ctime` identity. A shared,
world-readable, symlinked, hardlinked, replaced or mutated input yields HOLD
before any HUMAN decision is applied or confidential file bytes are returned.
The original source-owner `lightup.lab_inspect` and any scope, grant, scanner
or CI gate are unchanged.

If a trusted local browser writes a `PRIVATE-reconcile-browser-decisions.csv`
or an encrypted HUMAN packet into a normal-permission Downloads folder,
move it deliberately to a **trusted local owner-only** destination, inspect
file ownership, then set owner-only permissions *before* native use.
For example on Linux on your own trusted workstation:

~~~sh
mkdir -m 700 ./private-restricted
mv ./Downloads/PRIVATE-reconcile-browser-decisions.csv ./private-restricted/
chmod 600 ./private-restricted/PRIVATE-reconcile-browser-decisions.csv
~~~

Do not run these commands on shared/foreign-owned files, broaden permissions,
force symlink traversal, bypass a refusal or imply that local UID/mode checks
authenticate the sender, actual customer consent, original evidence, a fix
or security release. The original browser downloads remain the user's
responsibility. No automatic chmod, deletion or data disclosure is performed.


## Complete portable software-only OFFLINE assessment workroom kit

The source-controlled [software_bundle.py](software_bundle.py) packages
the complete **existing** offline disclosure + HUMAN editor, native
encrypted source-free review CLI, two-reviewer reconciliation terminal
and browser, and BOTH actually prebuilt single-file local HTML interfaces
into one deterministic, fixed-name **unsigned software-only**
`LightUp-PRIVATE-Assessment-Offline-Kit.zip`.

This is intentionally an operator software kit, not a source packet,
customer assessment result, verified evidence, approval record, secret
store, scan workflow, credential grant or signed release. The 18
explicitly allowlisted source files and one deterministic
`MANIFEST.json` are the **only** ZIP members; every actual included
software byte is recorded with its size and SHA-256. Fixed ZIP member
names/permissions and timestamps make a repeatable source-only build.
The original held `lightup.lab_inspect` from source-owner #1610 is NOT
vendored or replaced; the original preflight command still refuses to
run without the separately installed legitimate original inspector.
Nothing in this bundle can bypass authenticated current client/operator
consent, action-time revocation, independent owner/security/privacy/
browser/crypto review or HUMAN GO.

To rebuild from exact downloaded source code in a trusted
offline Python environment:

~~~sh
python3 assessment-disclosure-preflight/software_bundle.py
~~~

It publishes a new owner-only ZIP exclusively next to the source; it
cannot overwrite another existing file, follow symlink source assets
or add arbitrary original PRIVATE customer materials.
To inspect an existing original deterministic software ZIP without extracting
or executing its files:

~~~sh
python3 assessment-disclosure-preflight/software_bundle.py \
  --inspect ./assessment-disclosure-preflight/LightUp-PRIVATE-Assessment-Offline-Kit.zip
~~~

The offline inspector rejects unknown, duplicated, symlink-like,
noncanonical, reordered, oversized or changed members, compares all 18
source asset SHA-256 values with the strict embedded unsigned manifest,
checks literal-false authority flags and finally compares the COMPLETE
ZIP bytes with a reproducible rebuilt original software kit. It opens no
targets, creates no files and never extracts source into the filesystem.
An invalid/corrupt ZIP yields a clear HOLD instead of a Python traceback.
A successful match is only locally deterministic software-byte custody;
it does **not** prove that this ZIP, manifest or source came from the
right sender, that reviewers or clients are authenticated, that any
security evidence is real, or that any CI/release gate was approved.
Extract it only into a trusted owner-controlled local directory and
open the existing `standalone.html` or
`reconcile-standalone.html` with no web server.
The original multi-file HTML/CSS/JS and static builders are included
for transparent locally controlled rebuilding. Verify the unsigned
source inventory against an independently trusted source/commit:
SHA-256 equality is not a digital signature, authorship proof, CI gate,
consent or a release approval. Do not extract or send it on behalf of
a client without the original separate authorization.


### Sixth product: offline encrypted final HUMAN result directly from browser

The **existing two-reviewer local browser** now completes an end-to-end
**non-authorizing HUMAN handoff** without creating a new plaintext
final HUMAN report or CSV file. It does not run an assessment, activate
a target, authenticate a client or grant any release.

1. Load the exact original unsigned PRIVATE receipt and both completed
   HUMAN reviews (native CSV, encrypted .luhd, or encrypted .luhb). The
   browser re-admits the receipt and each exact original plaintext HUMAN
   CSV and their SHA-256 identities.
2. Compare all original ordinals and explicitly assign A/B/HOLD, with a
   nonblank bounded local reason for A/B. Every HOLD remains `unreviewed`,
   even when both reviewers agree.
3. First **export and protect the source-bound PRIVATE A/B decision CSV**;
   it contains both reviewer plaintext-byte digests and all HUMAN
   justifications. If any choice or reason subsequently changes, another
   decision-CSV export is **mandatory** before the sealed result may be
   generated. This prevents the browser from silently exporting an outcome
   whose separately retained decision rationale is stale.
4. Enter a NEW 14–256-character password twice and explicitly approve
   local encryption. The original LightUp `LightUpHumanVault.sealBundle`
   encrypts the identical unsigned receipt bytes plus selected HUMAN
   rows, in their original six-column native HUMAN CSV format, using
   AES-256-GCM, PBKDF2-SHA256 and a fresh salt/nonce. The result is a
   **single `PRIVATE-browser-reconciled-human.luhb`**, without writing
   a new plaintext final CSV or report. The browser verifies the
   source/session/selection revision after asynchronous encryption before
   allowing download; a subsequent change HOLDs the stale operation.
   Password inputs are cleared on both success and refusal, without
   a claim of secure erasure from browser or OS memory.
5. Independently choose a **source-free counts-only export**, using
   the existing native HUMAN stage names and minimum cohort floor of
   five. The original small-cohort and any nonzero under-five stage
   breakdown are suppressed. This is NOT guaranteed anonymity and
   requires the actual recipient/privacy review before any disclosure.

The encrypted bundle is compatible with the existing local
`human_review.py render --bundle` and the original local HUMAN studio
`.luhb` importer. It carries **the original unsigned receipt and
selected stage/question/action data, not the original A/B decision
justification**; keep the separate reviewer-bound decisions CSV for
source-identity and accountable HUMAN choice review. Native
`reconcile.py finalize` remains the stricter offline path that
reopens the original two reviewers and the saved choices. Do not
treat a browser-created encrypted file as proof of independent
review, source authenticity, receipt provenance, approved assessment,
cryptographic sender identity, authenticated current client/operator
consent or permission to send anything externally. Original CI,
review, named permanent runner, action-time revocation and HUMAN GO
remain mandatory for release.


### Human-visible final preview before sealing

The original A/B standalone workroom now includes a **complete final
selection preview** above its encrypted-result controls. All ordinals
are represented, even if a search or unresolved/selected filter hides
them in the comparison table. It shows exactly which operator-selectable
review A/B stage would be included and which unselected rows become
`unreviewed` without inherited question/action text. The operator's
explicit selection reason is visible, while sensitive reviewer
questions/actions are hidden in closed expandable sections until the
local HUMAN operator chooses to view them. The preview uses only
`textContent` for untrusted HUMAN material; it does not interpret
markup or load remote resources. Changing A/B/HOLD immediately
reconciles active filtered views and regenerates the full preview.
The preview is **not** a new security verdict, disclosure, client
consent, reviewer authentication or release; it makes the output the
human is deciding to encrypt understandable before the irreversible
local download.
