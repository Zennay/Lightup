# LightUp PRIVATE lab disclosure preflight

**CURRENT SOURCE DELIVERY — DRAFT/HOLD:** The up-to-date portable PRIVATE
two-reviewer workroom is [reconcile-standalone.html](./reconcile-standalone.html)
(rebuilt source-only at commit `9d3e561`). It supports original
HUMAN selection, encrypted native-compatible continuation, read-only receipt
and complete counts reopening, plus explicit privacy-minimal PRIVATE local
receiving records with unsigned byte identities. [The Python native receiver](./reconcile.py)
accepts either `reopen --received-csv ... --received-counts ...` for a
complete original-format PRIVATE HUMAN CSV, or `reopen --encrypt-result
--received-bundle ... --received-counts ...` for an encrypted browser handoff.
The bundled `LightUp-PRIVATE-Assessment-Offline-Kit.zip` now contains the current
complete two-reviewer browser sources, native original receiving commands and
a new [PRIVATE offline start page](./kit-home.html). Open `kit-home.html`
after extracting into trusted owner-only storage. The unsigned
`software_bundle.py --verify-current` command compares the complete ZIP
with these **exact installed source bytes** and refuses stale copies.
This confirms neither genuine provenance nor security, release or consent;
all original gates remain mandatory.


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

## One-command PRIVATE inbox + HUMAN worksheet workroom

The native [private_inbox_workroom.py](./private_inbox_workroom.py) publishes
the source-free dashboard and its exact matching SHA-bound HUMAN worksheet
together, through one exclusive private publication. All original rooms are
admitted first; if any input fails, none of the four output names is published.

~~~sh
mkdir -m 700 ./owner-private-workroom
python3 assessment-disclosure-preflight/private_inbox_workroom.py \
  --private-parent ./owner-private-inbox \
  --room review-001 --room review-002 \
  --private-output-dir ./owner-private-workroom
~~~

The output directory receives the portfolio HTML/CSV/JSON and
`PRIVATE-inbox-actions-template.csv`. It must be an **empty existing separate**
owner-only 0700 directory outside the original inbox tree. Already populated
destinations now HOLD before publication, matching the exact-inventory
read-only saved-workroom reopening contract. Optional `--full-reopen` requires a trusted
interactive terminal and exact `REOPEN` confirmation; it performs the
unchanged original HUMAN reopener for every selected room before publishing.
Exit 2 is REVIEW_ONLY; exit 3 is HOLD. This does not authenticate a source,
grant consent or authorize scanning/release. Edit the template in the offline
Studio and continue with native `private_inbox_actions.py finalize`.

## Native original PRIVATE HUMAN inbox follow-up actions

A new [fully offline PRIVATE HUMAN action browser Studio](./private-inbox-action-studio.html)
loads an already prepared complete native six-column template and allows
slot-by-slot source-free status, discussion-role and HUMAN text editing,
in-memory filters, an atomic bulk proposal for status/role on only visible
slots with one reversible HUMAN-only Undo, and a full original-order CSV
export. Every proposed row is admitted before any bulk change; a conflicting
worksheet state refuses the entire batch. An individual edit invalidates Undo
so it cannot overwrite newer choices. CSV export now has a separate aggregate
preview and explicit download confirmation; any row edit or bulk change
invalidates the preview, and filtered-out original slots remain included. No
HTTP, storage, background save or remote action; the original unchanged native
`private_inbox_actions.py finalize` is still required to admit every complete
exact source-bound row before publishing PRIVATE outputs.
The [source-bound PRIVATE HUMAN action guide](./PRIVATE-INBOX-ACTIONS.md)
and bundled `private_inbox_actions.py` complete the review workflow after
`private_inbox_board.py` generates the original source-free board JSON:
native `prepare` exports a fresh original slot-ordered HUMAN action template,
`reopen-template` checks the saved original standalone template read-only,
`finalize` requires all original slots and explicit human notes/statuses and
writes a separate PRIVATE owner-only HTML/CSV/JSON discussion pack, and
`reopen` checks the entire saved three-file inventory and byte bindings
read-only. Every native reopen requires an owner-owned 0700 output directory
with exactly the expected regular owner-owned 0600 unlinked files; stray names,
symlinks, changed inputs and altered output bytes produce HOLD. The existing
combined workroom's `--saved-workroom-dir` mode now shares that strict
four-file custody boundary. The standalone `reopen-template` is only for a
single-file `prepare` destination: for the recommended four-file workroom,
use `private_inbox_workroom.py --saved-workroom-dir` with the original
room selection instead. None of these read-only checks establish identity,
authentic chronology, consent, original evidence validity or release.
Human role labels are **proposals**, not actual assignments. Both the browser
Studio and native finalizer reject Unicode format/control characters and
NFKC-disguised spreadsheet formula prefixes in human CSV notes; native
finalization remains authoritative if the CSV was edited outside the browser.
A completed discussion is expressly **NO RELEASE**: it is not a verified
finding, client/operator consent, original source identity or any activation
approval.

~~~sh
python3 assessment-disclosure-preflight/private_inbox_actions.py --help
~~~

## Source-free multi-room HUMAN inbox board

New native [PRIVATE multi-room inbox board](./PRIVATE-INBOX-PORTFOLIO.md)
collects up to twelve explicitly named original PRIVATE received HUMAN
rooms into one fresh owner-controlled HTML/CSV/JSON portfolio. It reads the
original full local inventory and original seven-column source-free HUMAN
decision material without leaking room names, source paths, free-text notes,
original source hashes, or private customer data into the board. Each room
is represented by an ephemeral input-order slot and literal A/B/HOLD counts.
The entire product is read-only against original rooms; 0600 handoff files
are written exclusively into a separate existing owner-owned 0700 folder.
An explicit trusted TTY `--full-reopen` option allows a HUMAN operator
to request the original native full source-bound receipt/reviewer/result
reopening for EACH selected room, without modifying source files. A cancelled,
noninteractive or refused original reopen causes HOLD for the whole board;
even an original REVIEW_ONLY is never a security or authorization verdict.
This board explicitly does **not** decrypt or perform each original full
HUMAN source-bound reopener: the unchanged separate native
`private_reopen.py` is still necessary. REVIEW_ONLY/HOLD only, no PASS.

~~~sh
python3 assessment-disclosure-preflight/private_inbox_board.py --help
~~~

## Browser download → PRIVATE owner-only receiving inbox

The new [offline PRIVATE HUMAN inbox](./PRIVATE-BROWSER-INBOX.md) provides a
complete receiving operation instead of asking the operator to trust permissive
browser Downloads storage. For a guided source-only offline operator flow, run
`private_intake_wizard.py` in a trusted local interactive terminal: no path
echo, one original input role per prompt, original encryption mode choices,
and explicit RECEIVE confirmation. The wizard calls exactly the same underlying
source-bound PRIVATE intake and never grants any review status beyond
REVIEW_ONLY/HOLD. Native `private_intake.py` imports the original
PRIVATE unsigned receipt, both reviewer CSV/encrypted source files, complete
HUMAN decision CSV, one original full final plaintext/encrypted result and its
separate suppressed counts CSV, into a new owner-only 0700 room with 0600 files.
All original source/reviewer decisions, decrypted result when applicable and
counts are re-admitted by the **original unmodified `reconcile.py reopen`**.
Any mismatch results in HOLD with ordinary rollback of newly created files.
Original Downloads files remain untouched and may still be insecure.

~~~sh
python3 assessment-disclosure-preflight/private_intake.py --help
~~~

Original received HUMAN rooms can then be **reopened without writing files**
via the additional native `private_reopen.py --private-parent ... --room ...`.
It admits only exact current owner-owned private files, the entire original
unsigned byte inventory (duplicate keys and unexpected/missing files are HOLD),
and delegates again to the unchanged original full `reconcile.py reopen`.
Neither a local digest nor repeat reopening verifies genuine customer identity,
reviewer independence, evidence, consent, resolution or release.

Only after full original reopening does the room contain an additional
PRIVATE unsigned receipt of exact local file lengths and SHA-256 with
all genuine authority flags FALSE. It authenticates nobody, proves no findings,
and is never permission to publish or launch assessments. Both this inbox
and its detailed operator guide are bundled in the current **source-only**
offline ZIP; they perform no network or target actions.

## Browser-generated COMPLETE PRIVATE HUMAN result: encrypted or plaintext

The source-only [current one-file offline workroom](./reconcile-standalone.html)
now offers **two original-format result exports**, both guarded by the separate
already exported, exact-byte-digested seven-column A/B/HOLD decision CSV:

- **Seal PRIVATE selected HUMAN result (.luhb)**: the original receipt and
  complete selected original-format HUMAN rows remain password-encrypted in
  the original native-compatible PBKDF2/AES-256-GCM format.
- **Export complete UNENCRYPTED PRIVATE HUMAN CSV**: an explicit separate
  opt-in with an additional confidentiality confirmation, containing every
  original ordinal and its selected stage, question and next action in the
  original six-column native format. HOLD ordinals become literal
  `unreviewed` with empty private notes. All hidden/filter-inactive ordinals
  remain present. This is a deliberate PRIVATE plaintext download; move it
  directly to owner-only 0600 storage and avoid onward sharing.

In either path, the separate complete source-bound A/B/HOLD decision CSV
remains necessary for the HUMAN reason trail, and the independent suppressed
counts export is still required before native receiving. The exact original
PRIVATE receipt, both original reviewer submissions and all source-bound
decisions must re-admit through original `reconcile.py reopen`, with
`--received-csv --received-counts` for plaintext or
`--encrypt-result --received-bundle --received-counts` for ciphertext.

The receiving record export additionally binds the SHA-256 of the **actual
browser-generated current decision CSV**, along with original source/reviewer
and saved result/count bytes. This is unsigned **byte equality only**: neither
a browser download nor its SHA guarantees file persistence, producer identity,
consent, finding correctness, recipient approval, authorization or live release.
All actual CI/source-owner/privacy/security/browser review and action-time
consent/HUMAN GO gates stay mandatory.

## Manual PRIVATE local receiving record — no authority

The current [single-file offline HUMAN workroom](./reconcile-standalone.html)
also provides **Export PRIVATE local receiving record (.html)** after a saved
plaintext or encrypted result **and its entire suppressed-counts handoff**
have been admitted against the exact original PRIVATE receipt, both independent
HUMAN input files and all current original source-bound A/B/HOLD decisions.

This explicit local export contains only SHA-256 byte identities of the
unsigned original PRIVATE receipt, each separately provided original reviewer
CSV, **the exact generated complete seven-column original A/B/HOLD HUMAN
decision CSV**, the actually reopened result and its separate counts file,
together with the declared mode, appropriately suppressed source count and
literal false authority flags. The browser hashes the exact generated PRIVATE
decision bytes *before* offering the download and refuses to promote those bytes
to the current decision state if the source or HUMAN selections changed while
hashing. The resulting local decision SHA demonstrates only what this browser
generated, not that the browser successfully persisted a file to disk or that
any signer was authenticated. It has **no reviewer note, question, next-action, reason or
original lab finding content**. It is scriptless with a restrictive offline
CSP. The receipt remains PRIVATE; hashes can correlate data and establish no
client/operator identity, signature, consent, reviewer independence,
independent validation, fixed vulnerability, release or recipient rights.

If a HUMAN selection changes, a fresh source is loaded or the browser session
ends, the prior local receiving record becomes unavailable: the operator must
export the new complete decision CSV, reopen the original result and suppressed
counts, then explicitly request a new receiving record. A failed admission
never issues such a record. Normal browser downloads may not inherit 0600
permissions; move all PRIVATE records into owner-controlled storage and
continue to rely on the separate original native source-bound reopener for
local trusted-machine custody. This is **not** a signed audit certificate and
has not passed independent browser/cryptographic security review.

## Standalone-to-native PRIVATE handoff receiving

The original [single-file offline HUMAN desk](./reconcile-standalone.html) now
contains a **read-only saved handoff receiver**. After loading the exact
unsigned PRIVATE receipt and both originally submitted HUMAN reviewer files,
manually restoring or editing all source-bound A/B/HOLD choices and exporting
the complete current 7-column PRIVATE decision CSV, select an already saved
complete plaintext native HUMAN CSV or an encrypted `.luhb`, **plus its own
separate suppressed counts file**. Reopening compares every selected stage,
question and action to the unchanged current selections and requires the
complete source-free original counts table, including literal false-authority
fields, to match. An encrypted `.luhb` must include the exact original PRIVATE
receipt bytes. A mismatch refuses and keeps the current local HUMAN workroom.

The native `reconcile.py reopen` now also accepts the **actual browser-exported
files**, which use all-quoted original-format CSV and arbitrary local downloaded
basenames. It does not require renaming or regenerating a native output just
to perform the original full source-bound recipient check. Browser counts may
differ in CSV quoting from native output: native reopening compares the complete
parsed, fixed field/value table and all original HUMAN rows; the unchanged
default native files still use byte-for-byte equality.

~~~sh
# Only on the owner-controlled offline workstation, after storing the exported
# files and the ORIGINAL source/reviewer/decision inputs with 0600 permissions.
# The --private-output-dir remains an existing owner-only 0700 directory.
python3 assessment-disclosure-preflight/reconcile.py reopen \
  --receipt ./owner/PRIVATE-receipt.json \
  --a-csv ./owner/original-reviewer-A.csv \
  --b-csv ./owner/original-reviewer-B.csv \
  --decisions ./owner/PRIVATE-reconcile-browser-decisions.csv \
  --encrypt-result \
  --received-bundle ./owner/PRIVATE-browser-reconciled-human.luhb \
  --received-counts ./owner/PRIVATE-browser-reconciled-counts.csv \
  --private-output-dir ./owner/unused-private-receiving-desk

# An independently saved complete plaintext final CSV uses the same original
# inputs and source-bound HUMAN decisions, but omits --encrypt-result.
python3 assessment-disclosure-preflight/reconcile.py reopen \
  --receipt ./owner/PRIVATE-receipt.json \
  --a-csv ./owner/original-reviewer-A.csv \
  --b-csv ./owner/original-reviewer-B.csv \
  --decisions ./owner/PRIVATE-reconcile-browser-decisions.csv \
  --received-csv ./owner/PRIVATE-reconciled-human.csv \
  --received-counts ./owner/PRIVATE-browser-reconciled-counts.csv \
  --private-output-dir ./owner/unused-private-receiving-desk
~~~

The native CLI enforces a single input mode: `--received-csv` (plaintext)
or `--received-bundle` with `--encrypt-result`. The separate complete
`--received-counts` file is mandatory in either explicit receiving mode.
Every private reviewer and decision is re-admitted before comparing the entire
logical CSV content and all declared count/authority fields. Ordinary native
reopening without explicit receiving arguments still retains byte-exact
comparison of the originally published native artifacts.

This step reads original files but does not create new outputs, run a scanner,
interpret finding validity, authenticate the sender, grant consent, approve a
recipient or release anything. Exit 2 remains **REVIEW_ONLY**, exit 3 **HOLD**.
It is not a browser crypto security audit or an independent proof of original
client authority. The current tracked source-only ZIP is freshly generated
from this branch, with an offline start page and two complete browser workrooms.
Verify that it matches your local source tree using
`software_bundle.py --verify-current`; unsigned matching bytes do not
authorize publication, external sharing, assessments or a live release.

## Read-only complete HUMAN handoff reopening

`reconcile.py reopen` is a **new independent receiving operation** for an
already-prepared PRIVATE two-reviewer HUMAN handoff. On the same trusted offline
machine, provide the original unsigned PRIVATE receipt, both separately saved
original reviewer submissions, the manually completed decision CSV, and the
owner-only 0700 output directory. The operation re-admits the exact original
receipt, original reviewer CSV bytes and every original decision; reconstructs
the native complete HUMAN selection and counts; and compares all plaintext
native handoff files **byte-for-byte** against their expected values.

For a deliberately encrypted `--encrypt-result` handoff, `reopen` instead
asks for the original private bundle passphrase through the existing native
no-echo password reader, decrypts the previously published `.luhb` only in
memory, and checks the original receipt and complete HUMAN selection against
the same unchanged source inputs. It also independently checks the counts
handoff bytes. No plaintext HUMAN CSV is written by encrypted reopening.

~~~sh
# The original operator receipt/review files and completed decisions must
# still be available privately; no active scanning or publication occurs.
python3 assessment-disclosure-preflight/reconcile.py reopen \
  --receipt ./private/PRIVATE-receipt.json \
  --a-csv ./private/reviewer-a.csv \
  --b-csv ./private/reviewer-b.csv \
  --decisions ./private/PRIVATE-reconcile-decisions.csv \
  --private-output-dir ./private/reconciled-output
# For the encrypted finalization, use the same options plus --encrypt-result.
~~~

Exit code **2** means the **declared unsigned source-free PRIVATE HUMAN files**
matched this local read-only reconstruction and still require manual review.
Any changed or missing output, mismatched reviewer/decision, invalid source,
incorrect passphrase or altered counts yields **3 / HOLD**. No new outputs,
labels, verification, consent, customer disclosure, scan, or authorization are
created. Successful local reconstruction does **not** prove reviewer identity,
original evidence provenance, correct findings, remediation or security.

## Complete two-reviewer publication (PRIVATE, no release)

The native `reconcile.py prepare` and `reconcile.py finalize` paths now use
`human_review.publish_many` to assemble their entire PRIVATE deliverable set
before exposing any final filenames. The original reviewer receipt and two
submitted review byte hashes remain bound to every decision; this does not
authenticate either reviewer or original assessment evidence.

- **Prepare** stages the exact decision template and the scriptless private
  comparison together; either both finish or normal publish failure removes
  both newly created final names.
- **Finalize plaintext** stages the selected complete HUMAN CSV, comparison
  report, and small-cohort-suppressed PRIVATE counts together.
- **Finalize encrypted** stages the encrypted HUMAN bundle and its distinct
  small-cohort-suppressed PRIVATE counts together. Decrypted output is never
  separately staged in that path.
- Any existing final name refuses the entire new handoff rather than
  overwriting it. Stage files and outputs use one pinned owner-only 0700
  directory descriptor and exclusive 0600 file creation.

A hard crash/power loss may leave incomplete final sets or hidden PRIVATE
staging files: this is **rollback on normal failure, not a filesystem-wide
transaction**. Recipients must not infer completeness or approval from partial
files. Always inspect the complete intended set, original HUMAN source binding
and actual transfer authorization. PRIVATE counts are not automatically anonymous,
and REVIEW_ONLY/HOLD remain the only outcomes.

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
store, scan workflow, credential grant or signed release. The 33
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

### Open the actual offline kit

To prevent permissive extraction, run the included source-only
`private_install.py` locally from a trusted LightUp source checkout.
It checks the original unsigned ZIP without executing its contents, requires
an existing user-owned private 0700 parent, creates a completely NEW
0700 child with 0600 software files, refuses existing destinations and
attempts to remove only newly created files after normal failure.
It never claims package authenticity, grants or customer rights.

~~~sh
mkdir -m 700 ./owner-private-kit-parent
python3 assessment-disclosure-preflight/private_install.py \
  --zip ./assessment-disclosure-preflight/LightUp-PRIVATE-Assessment-Offline-Kit.zip \
  --private-dir ./owner-private-kit-parent/installed
~~~

The installer deliberately returns **2 (REVIEW_ONLY)** when it copied the
strictly allowlisted unsigned software; invalid input, non-private parent
or existing output is **3 (HOLD)**. The console does not execute scripts,
open a browser, scan, run models or contact a network. The destination
contains `assessment-disclosure-preflight/kit-home.html`.
Open [kit-home.html](./kit-home.html) locally from that installed folder
for two direct, functional offline workroom links. The page is a script-free static navigation guide with a
network-denying CSP; `kit-home.css` remains a separate allowlisted source
asset. The original lab inspector is **not** in this kit and must be provided
separately by its actual owner before any native original-artifact preflight.

To verify that the complete currently installed ZIP is not a stale prior
software build **without** extracting or running any embedded source:

~~~sh
python3 assessment-disclosure-preflight/software_bundle.py --verify-current
~~~

An exact canonical unsigned ZIP/source match returns **2 (REVIEW_ONLY)**,
printing the local ZIP SHA-256; an out-of-date, altered, missing or otherwise
noncanonical archive returns **3 (HOLD)**. The comparison includes this
README, the offline start page and both complete portable browser workrooms.
This does not establish genuine sender, ownership, identity, permission,
confidentiality, security approval or human GO.

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
noncanonical, reordered, oversized or changed members, compares all 33
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


## Seventh product: reversible HUMAN selections and scoped HOLD

The offline [two-reviewer studio](reconcile-standalone.html) now provides
a real **memory-only HUMAN decision history**, not just a one-way export.

- Every explicit reviewer A/B/HOLD change creates a reversible checkpoint.
  HUMAN reason typing is grouped into short editing bursts to keep the
  40-step in-memory history practical. A restored original source-bound
  decision CSV also forms an undo step. Undo and redo never take actions
  against assessment targets, users, clients, networks or remote systems.
- Filter to matching original ordinals by reviewer-text differences,
  stage, status, or local search. **Set selected matching rows to HOLD**
  shows exactly which original ordinals would be affected and requires
  affirmative HUMAN confirmation. It changes only currently matching
  **explicitly selected** rows, clearing their decision reasons. It does
  not silently touch nonmatching or already-held originals.
- Undo, redo, restored choices and bulk HOLD each invalidate the previous
  saved seven-column A/B decision export. A NEW exact reviewer-bound
  decision CSV export is compulsory before the encrypted selected HUMAN
  continuation or source/note-free counts download is reenabled. A stored
  old decision file cannot be silently treated as current authorization.
- Everything stays in page memory until deliberate user download; no
  autosave, remote logging, clipboard capture, localStorage, IndexedDB
  or new original source tracking is introduced. Opening a different
  receipt or clearing the session drops reversible history; browser/OS
  memory secure erasure is not claimed. The unverified original receipt,
  external source-owner inspection and all real release gates remain
  unchanged.

This is a HUMAN correction/triage convenience, **not** a source
authenticator, consent registry, automatic selection, reviewer identity,
verified finding, scan, grant, security verdict or approved disclosure.


## Eighth product: PRIVATE no-notes HUMAN handoff cover

After **exactly exporting the current reviewer-byte-bound A/B decision CSV**,
the local two-reviewer browser offers an independent, scriptless
`PRIVATE-browser-HUMAN-handoff-cover.html` export. The HUMAN must explicitly
approve the local download. The cover includes only the original unsigned
source-free receipt hash, the SHA-256 of both exact original completed HUMAN
CSV streams (decrypted bytes, never ciphertext), every original local ordinal
and declared kind, explicit A/B/HOLD choice and selected non-authorizing
HUMAN stage. It records how many ordinals remain HOLD with no inherited
notes.

**It deliberately does NOT include the original reviewer questions,
proposed next actions, or the HUMAN explanation/reason for choosing A/B.**
The separately retained exact seven-column PRIVATE decision CSV is still
required for those reasons and for native `reconcile.py finalize`.
The cover has no JavaScript, form submission, network connections, remote
assets, external links or scripts. HTML is escaped when generated.
No original laboratory source evidence is embedded. This is **not an
anonymous public release**: receipt/reviewer hashes, aggregate source
kinds and review stages may be confidential or correlatable. Recipient,
legal basis, source owner, actual current client/operator authenticated
consent and action-time revocation must be checked independently. The
cover cannot authorize disclosure, prove identity, verify security
findings, grant scope or advance project release gates.

Changing a HUMAN decision, restoring an older draft, undoing/redoing
a choice, or applying a filtered bulk HOLD invalidates the previous
decision CSV and **also blocks** the cover download until the updated
current A/B decisions are explicitly exported again. No persistent
browser storage or automatic sending is added.


## Read-only reopen of the complete combined PRIVATE inbox workroom

The one-command native workroom can now re-admit a previously published four-file output without rewriting it. Supply the same original PRIVATE parent and exact room names in the same manual slot order, then set --saved-workroom-dir to the existing owner-only 0700 workroom directory. The command rebuilds the expected board HTML, source-free CSV, exact JSON manifest and matching HUMAN action template from the current original room bytes; missing/extra files, changed source/decisions, a different room order, or any changed output byte returns HOLD. Files must remain owner-only 0600 and the saved directory owner-only 0700.

Example (the same --full-reopen choice must be used as when the workroom was created):
python3 assessment-disclosure-preflight/private_inbox_workroom.py --private-parent ./private-received --room owner-room-01 --room owner-room-02 --saved-workroom-dir ./private-workroom --full-reopen

Omit --full-reopen only if the original workroom was created without it. When enabled, the command requires a trusted interactive terminal and explicit REOPEN confirmation, then reopens each original room through the unchanged native source-bound receiver before comparing the saved bytes. This is read-only custody/re-admission, not source authenticity, identity, consent, a security verdict, authorization or release. No original files or workroom outputs are modified.


## Compare saved HUMAN inbox revisions without exposing note contents

The browser Inbox Action Studio now compares a prior complete six-column HUMAN
worksheet against the current in-memory draft. Both revisions must be valid
complete CSVs with the same original board SHA, all original ordinals in the
same order, and every status/role/note row admitted against the existing
worksheet rules. Different source bytes, incomplete rows, malformed UTF-8,
oversized files or a stale/invalid current draft produce HOLD with no partial
delta. Editing a row, applying or undoing a bulk proposal invalidates the
comparison; the export rechecks that the current full worksheet still matches
the exact compared draft.

The on-screen changed-only table shows stage/role transitions and whether the
question or next-action text changed, but never displays either private text.
Its optional CSV similarly omits note contents, board hashes, filenames and
identities; it carries only slot ordinals, changed field names, stage/role
values, boolean text-change flags and explicit false chronology/source/consent/
authorization/release fields. "Prior/current" is operator-supplied order, not
authenticated chronology. This is a local HUMAN planning aid, not a signed
audit log, source authentication, remediation proof, consent or authorization.
The existing source-bound native finalizer remains the separate receiving step.


The same source-bound revision delta is available from the native
private_inbox_actions.py compare command for operators who do not use the
browser. It independently re-admits both full original six-column HUMAN CSVs
against the exact current source-free board before atomically publishing
scriptless HTML, CSV and JSON. Only changed ordinal/field labels, stage/role
transitions and boolean note-change flags are emitted; private question and
next-action text is never included. Original input files and current HUMAN
plans remain unchanged. The unsigned report is not authenticated chronology,
remediation evidence, consent or authorization.


## Multi-revision original PRIVATE HUMAN discussion history

Use [private_inbox_history.py](./private_inbox_history.py) to admit 2–8
**complete saved source-bound HUMAN worksheets** against exactly the same
original source-free board. In explicitly supplied order it builds a full
scriptless offline HUMAN stage/role progression for every original slot,
privacy-minimal per-round change booleans and a three-file source-free
PRIVATE HTML/CSV/JSON history plus a fourth private CSV grouping
the most recently declared HUMAN attention and suggested role for each slot. No private question or next-action text,
source identifiers, evidence, filenames or board digests appear in outputs.
Manual ordering does not authenticate chronology, actors or consent.

The `build` command rejects source-tree-nested output and exclusively publishes into a fresh empty owner-only
0700 directory; `reopen` re-admits current exact original board and all
complete selected HUMAN sheets, then verifies original saved four-file
inventory, mode 0600, regular unlinked file identity and byte equality
without writing anything. It does not change the active HUMAN plan.
The full operator route, examples and security warnings are in
[PRIVATE-INBOX-HISTORY.md](./PRIVATE-INBOX-HISTORY.md).


### Local interactive history browser (source-free and read-only)

The [PRIVATE History Desk](./private-inbox-history-studio.html) opens a
previously produced `PRIVATE-inbox-HUMAN-history.json` in the browser and
provides an interactive manual-round selector, source-order slot cards,
status/role filters, adjacent changed-field indicators, per-round counters,
latest human attention table and private printing. It reads no source
evidence or complete HUMAN notes and cannot write/import to the native
HUMAN plan. This is a **viewer**, not a replacement for native original
four-file custody reopening, release approval or human consent.

This standalone set consists of the HTML entry page, one adjacent JavaScript
file and one local CSS file. CSP allows only same-folder JS/CSS and denies all
network, storage/service and frame connections. It refuses ambiguous duplicate
JSON keys and unexpected schema/authority fields, incomplete stage histories,
falsely claimed no-release flags and inconsistent latest attention entries.
It retains the source-free report only in browser memory; use **Clear private
session** on shared devices. See the [history guide](./PRIVATE-INBOX-HISTORY.md).


### Portable one-file PRIVATE History Desk

The complete [single-file HUMAN History Desk](./private-inbox-history-standalone.html)
contains the same offline interactive browser interface with all HTML, CSS
and JavaScript physically embedded into **one file**. Its restrictive CSP
pins the exact source script and stylesheet by SHA-256; no network, storage,
external scripts, inline event handlers, scanning or assessment execution.
This is convenient for isolated offline review without a three-file software
directory. It still imports only the previously native-generated local
source-free history JSON and never authenticates that report.

Use `python3 private_inbox_history_package.py verify-current` to compare the
one-file version with the exact installed original HTML/CSS/JS source bytes;
REVIEW_ONLY (2) means equality of local unsigned bytes, not trusted identity
or security approval. After intentionally changing these original sources,
run `python3 private_inbox_history_package.py build --replace` to regenerate
only the owned one-file browser output. The software-only ZIP includes the
original source, builder and generated single-file browser.

### Direct original HUMAN sheet authoring in the offline browser

The [standalone PRIVATE History Desk](./private-inbox-history-standalone.html)
now creates source-free HUMAN history without Python: select one complete
original owner-private `PRIVATE-inbox-portfolio.json` and 2-8 complete saved
six-column HUMAN CSVs in manually chosen order. Browser Web Crypto SHA-256
checks exact original board bytes against every worksheet, including all slots,
allowed statuses/roles and safe HUMAN notes. Changed note contents are compared
only in browser memory and never included in output. Repeated snapshots,
duplicate JSON keys, malformed UTF-8 and authority claims are rejected.

A new private history opens in the existing interactive viewer immediately.
An explicit download of source-free JSON rechecks all source bytes first.
The browser retains file handles until the session is cleared; use only
trusted offline machines. Browser-generated JSON is unsigned and is NOT the
original native four-file 0700/0600 custody report. The native history
`build` and `reopen` commands remain required for independent saved-source
re-admission. No source identity, reviewer authority, consent, remediation,
scope clearance or permission to assess targets is created.

### End-to-end browser → original native PRIVATE custody

`private_inbox_history.py receive-browser` now receives the browser's
unsigned source-free history JSON together with the **same original** owner-
private board and 2–8 full HUMAN worksheets, performs an independent complete
native recomputation, rejects any mismatched/differently typed JSON fields,
and publishes the canonical four-file owner-only 0700/0600 native workroom.
`reopen-browser` independently re-admits saved output bytes read-only.
Use the exact command examples in [PRIVATE-INBOX-HISTORY.md](./PRIVATE-INBOX-HISTORY.md).
No client/reviewer/source authentication, consent, assessment or release is
created by a browser/native equality comparison.

### PRIVATE HUMAN arbitrary-round comparison and complete session clear

The [offline HUMAN History Desk](./private-inbox-history-standalone.html)
can compare *any earlier and later* manually ordered rounds, not only
adjacent snapshots. It distinguishes endpoint stage/role differences from
intermediate edits and reversals; private question/next-action flags mean
at least one edit occurred, not a different final text. The optional
unsigned source-free CSV always includes all original slots regardless
of display filters and explicitly denies source/chronology/authorization/
release authority.

The single action **Clear ALL private inputs and history** now discards the
native/browsed preview and the separate original HUMAN CSV/board file
selections together. Composed previews are invalidated when original
source-file choices change, and stale asynchronous native imports cannot
overwrite newer histories. No remote deletion, browser-memory wiping
guarantee, saved-download deletion or actual consent is asserted. Read
[PRIVATE-INBOX-HISTORY.md](./PRIVATE-INBOX-HISTORY.md) for privacy boundaries.

### New original native interval report (private HTML + CSV + JSON)

For any earlier/later HUMAN planning round pair, the included
[private_inbox_interval.py](./private_inbox_interval.py) builds and
read-only reopens a **complete, source-bound owner-private interval
dossier** using the original `PRIVATE-inbox-portfolio.json` and
all 2–8 complete original HUMAN worksheets. The native reporter
independently verifies all original source-free inputs before writing;
it never imports the browser's unsigned interval CSV as original source.
Outputs are scriptless HTML, all-slot privacy-minimal CSV and unsigned
source-free JSON, exclusively into a new empty 0700 folder with
owner-only 0600 files. Reopen enforces complete inventory and exact
recalculated bytes. Unlike simple endpoint differences, an intervening
status or role edit remains visibly flagged even if later reversed.
Note-change flags indicate only an edit happened at least once.

Command examples, native re-admission, privacy/consent and no-release
limitations are documented in
[PRIVATE-INBOX-HISTORY.md](./PRIVATE-INBOX-HISTORY.md). This is a local
HUMAN planning dossier, never a customer scan, authenticated finding,
remediation, staff assignment, consent record or security approval.

### Browser/native PRIVATE interval CSV column compatibility

The browser interval download and original native
`private_inbox_interval.py` CSV use the same column names, order, entire
original slot membership, original HOLD-count field, manually selected round
bounds, endpoint differences, intermediate edit flags and literal false
source/chronology/authorization/release columns. CSV field quoting may differ.
This is *format compatibility only*: the browser export is unsigned and is
never accepted as proof of original-source file custody, verified identity,
review, consent or release. Use the native source-bound build/reopen to
establish local original/private bytes independently.


## All-pairs PRIVATE HUMAN interval matrix

For 2–8 complete saved HUMAN revisions of the same original private inbox
board, `private_inbox_interval_matrix.py` creates a single local matrix of
every earlier/later pair (up to 28). The scriptless HTML, complete-slot CSV
and JSON are published together under the same owner-private 0700/0600
custody rules as the original interval dossier. The matrix distinguishes
endpoint stage/role changes from intermediate edits and includes unchanged
original slots. It exposes no question/next-action text and grants no
authority; manually selected round order is not authenticated chronology.

The `build --preview-only` mode admits and rechecks the same original board
and 2–8 complete HUMAN worksheets, then prints only aggregate round/slot/pair
counts. It does not render report files, create an output directory or publish
artifacts. Preview is REVIEW_ONLY, never approval or release.

See [PRIVATE-INBOX-HISTORY.md](./PRIVATE-INBOX-HISTORY.md) for the build, no-write
preview and read-only reopen commands, exact input requirements and privacy boundaries.

### Assessment interval matrix HUMAN follow-up (v2)

`private_inbox_interval_matrix.py build` produces an original-source-bound,
scriptless all-pairs interval matrix and a separate PRIVATE human follow-up CSV
for all original slots. Stage/role reversions and note edit counts are
*manual-order discussion signals only*, not remediation evidence, security
findings, permission, identity or authenticated timing. Output now consists of
four PRIVATE 0600 artifacts; `reopen` checks the original four byte-for-byte
against current admitted inputs, while `--preview-only` stays read-only.
See [PRIVATE-INBOX-HISTORY.md](PRIVATE-INBOX-HISTORY.md) for usage and gates.
