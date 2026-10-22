# LightUp · Assessment Lineage Desk

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** [Product issue #1596](https://github.com/Zennay/Lightup/issues/1596). This is a separate, strictly offline, private **human review** workspace. It is **not** a lab runner, evidence authenticator, scanner, tool dispatcher, access-grant issuer, consent validator, release system, or authority to touch a target.

## Standalone source integrity during regeneration

`python3 assessment-lineage/build_standalone.py` regenerates the one-file
offline application from the checked-in `index.html`, `app.js` and
`style.css` only. Exact singleton script/style source markers and forbidden
HTML closing tags are checked with explicit fail-closed exceptions, **including
when Python runs with optimization enabled** (where `assert` normally
disappears). The regenerated app contains exact SHA-256 CSP script/style
source pins and preserves all no-network/no-worker policy.

The builder now writes to a temporary sibling file, fsyncs the complete
public-code artifact and atomically replaces `standalone.html` only after
source validation and complete publication; an interrupted build does not
truncate the previous standalone file. This builds only **public offline
application code**, never uploaded private client/lab content, never
scans or executes an assessment. It is not independent browser approval,
original source-owner review or authorization to deploy.

## Native source-admission failure handling

The PRIVATE builder now rejects type-confused status and HUMAN-draft schema
fields with its normal non-authorizing `HOLD` result rather than surfacing
an input-dependent native exception. Nonfinite original JSON decimal numbers,
including exponent overflow and nonzero values that underflow to binary
floating zero, are refused before embedding source claims into the PRIVATE
workroom. Genuine zero exponent representations remain admissible. There
is no interpretation as detected security evidence and no modification of
the original browser's stricter scenario/comparator validation.

These are early local admission safeguards for untrusted originals, not proof
of source authenticity, absence of vulnerabilities or permission to run an
assessment. The native tool never executes a comparator, contacts a target,
releases a claim, authorizes a grant or grants consent.

## One-file PRIVATE report selection (1–8 finished comparisons)

The native offline `private_workroom.py` now accepts `--reports-file` as an
alternative to repeating `--report` on the command line. The file is a
current-user-owned, exact mode-0600 regular UTF-8 text file, with one canonical
**absolute** original completed-report path per LF-terminated line. The
recorded order is a deliberately chosen **human view only**; it does not prove
which original comparator report was created earlier.

```bash
umask 077
cat > /private/lineage-original-report-selection.txt <<'EOF'
/private/comparison-a/canonical-original.json
/private/comparison-b/canonical-original.json
EOF
chmod 600 /private/lineage-original-report-selection.txt
mkdir -m 700 /private/lineage-selected-workroom
python3 assessment-lineage/private_workroom.py \
  --catalog /private/source/original-lab-catalog.json \
  --reports-file /private/lineage-original-report-selection.txt \
  --output /private/lineage-selected-workroom/workroom.html
```

Use the **identical** `--reports-file` selection to later reopen that exact
packet with `--verify-existing`. The tool requires **either** 1–8 individual
`--report` options **or** one private `--reports-file`, not both.
An empty or oversized list, duplicate/relative/noncanonical filenames,
hidden bidi or control characters, symlinks, nonregular or hard-linked input,
changed bytes, or missing/private-source permission causes HOLD. Each listed
original completed report still goes through the unchanged original report
admission, including original HUMAN-draft digest binding. The selection list
is reread just before publishing or reopening; it is never embedded in the
PRIVATE HTML as source filenames.

This saves operator preparation time but grants no authority, identifies
no true reviewer, creates no report itself, runs no evaluation and sends
nothing to a target or service. Do not import an arbitrary source list from
an untrusted recipient.

## Exact original-source PRIVATE workroom reopen (read-only)

After building an owner-private workroom, the native builder can independently
reconstruct the expected **complete HTML bytes** from the same original catalog,
the same ordered 1–8 original completed reports, the same optional original
HUMAN draft, and the checked-in CSP-pinned offline application. The explicit
`--verify-existing` flag opens the already saved HTML as an owner-owned
mode-0600 non-symlink single-hard-link file, compares its exact bytes with
the reconstructed workroom and **never writes, repairs, regenerates or launches
the browser**. The output parent must remain current-user-owned mode 0700.
The output file may not alias any original private input.

```bash
python3 assessment-lineage/private_workroom.py \
  --catalog /private/source/original-lab-catalog.json \
  --report /private/source/original-cohort-a.json \
  --report /private/source/original-cohort-b.json \
  --output /private/lineage-room/private-review.html \
  --verify-existing
```

Omit `--verify-existing` only when explicitly creating a **new**
never-overwritten private packet in an already-existing mode-0700 folder.
A changed original source, missing packet, extra/replaced HTML bytes,
changed source ordering, unsafe source/output path or changed offline
application fails closed with HOLD. This is local byte consistency, not a
digital signature, verified original authorship, customer authorization,
independent HUMAN review or release permission. It does not contact any
target, network, scanner or external service.

## PRIVATE source-byte receipt and exact two-file reopen

Use optional `--private-receipt` to create an additional, **owner-private**
`*.private-lineage-receipt.json` next to the original PRIVATE HTML workroom.
This is useful when a human operator needs to reconcile which exact original
offline Studio catalog, ordered 1–8 original finished comparisons and optional
exact-source HUMAN draft were used to assemble a particular review desk.
Default single-file behavior is unchanged.

```bash
umask 077
mkdir -m 700 /private/lineage-original-review-room
python3 assessment-lineage/private_workroom.py \
  --catalog /private/source/catalog.json \
  --reports-file /private/source/report-selection.txt \
  --human-draft /private/source/private-human-draft.json \
  --output /private/lineage-original-review-room/review.html \
  --private-receipt

# Later: read-only exact reopen of both original private artifacts.
python3 assessment-lineage/private_workroom.py \
  --catalog /private/source/catalog.json \
  --reports-file /private/source/report-selection.txt \
  --human-draft /private/source/private-human-draft.json \
  --output /private/lineage-original-review-room/review.html \
  --private-receipt --verify-existing
```

### Optional scriptless PRIVATE source inventory

Add `--private-source-board` **together with** `--private-receipt`
to create an additional readable offline file
`review.private-lineage-source-board.html`, alongside
`review.private-lineage-receipt.json` and `review.html`.
The table contains one neutral original catalog row, one numbered row for each
human-selected completed report (01–08), an optional HUMAN-draft row and
the produced private HTML row. It displays local full SHA-256 values **only**
(no source paths, hostnames, finding IDs, notes, commands, client data or
embedded scripts). Its restrictive CSP forbids script, style and network
content. Rows are locally computed from original bytes and are not independent
original evidence.

```bash
python3 assessment-lineage/private_workroom.py \
  --catalog /private/source/catalog.json \
  --reports-file /private/source/report-selection.txt \
  --output /private/lineage-room/review.html \
  --private-receipt --private-source-board

# Later, prove the three locally saved original bytes still match source inputs:
python3 assessment-lineage/private_workroom.py \
  --catalog /private/source/catalog.json \
  --reports-file /private/source/report-selection.txt \
  --output /private/lineage-room/review.html \
  --private-receipt --private-source-board --verify-existing
```

All three artifacts are strictly private; no automatic recipient handoff or
network transfer exists. The full SHA-256 values are sensitive source
correlation metadata. These packets do not confirm source authorship, actual
HUMAN chronology, operator identity, client consent, scanner eligibility,
remediation, release or a real security finding. `--verify-existing` is
read-only; a missing/changed HTML, receipt, table or original source results
in HOLD. Without both opt-in flags, the normal single-workroom behavior
remains unchanged.

The source receipt stores only canonical private SHA-256 byte digests, original
report order/count, optional HUMAN-draft presence and the resulting HTML byte
digest. It never adds the original file paths, private source values or HUMAN
notes to anonymous exports. Its four authorization/consent/dispatch/release
flags and separate identity/origin/HUMAN GO fields are literally **false**.
The receipt **contains sensitive source-correlation hashes**: keep it mode
0600 under the same owner-only 0700 directory and never upload it as an
anonymous result. A local unsigned digest only demonstrates consistency with
available input bytes; it is **not** a signature, original authorship proof,
operator/client authentication, authorization, independent privacy/security
review, or evidence of a real finding or remediation.

Without `--verify-existing`, both destination filenames must be new.
The tool uses exclusive no-overwrite creation and 0600 modes; if a second
artifact fails to publish, only files it just created are removed. Existing
files remain untouched. With `--verify-existing`, both original inputs are
re-admitted and both artifacts' exact bytes are checked without any write.
Changing report order, original file bytes, HUMAN draft, checked-in offline
workroom renderer, HTML or receipt yields HOLD. Omitting `--private-receipt`
retains the existing single-HTML create and reopen behavior.

This feature does not invoke comparison, scan, network, model, grant, consent,
dispatch, release or active target access. Project remains INCUBATE M3/M7
PLAN/LAB ONLY · DRAFT/HOLD, subject to existing mandatory CI, source-owner,
security/privacy, separately authenticated client/operator consent and
action-time revocation, and explicit HUMAN GO before any main merge/release.

## Compare two PRIVATE source receipts without original data disclosure

The standalone native `compare_receipts.py` is an offline *operator-only*
continuity desk for two separately generated ORIGINAL PRIVATE receipt files,
such as a source selection from an earlier and later **human-chosen review
session**. This does not prove the sessions were created in that order.

```bash
umask 077
mkdir -m 700 /private/lineage-human-continuity-delta
python3 assessment-lineage/compare_receipts.py \
  --before /private/lineage-room-a/review.private-lineage-receipt.json \
  --after /private/lineage-room-b/review.private-lineage-receipt.json \
  --output-dir /private/lineage-human-continuity-delta

# Read-only reopening: original receipts and both outputs must still match:
python3 assessment-lineage/compare_receipts.py \
  --before /private/lineage-room-a/review.private-lineage-receipt.json \
  --after /private/lineage-room-b/review.private-lineage-receipt.json \
  --output-dir /private/lineage-human-continuity-delta --verify-existing
```

**Delivered files:** `lightup-private-lineage-source-delta.json` and
`lightup-private-lineage-source-delta.html`, both owner-only mode 0600
inside an existing separate, initially empty mode-0700 private directory.
The local HTML is scriptless with a network-denying CSP. It distinguishes
original catalog byte changes, HUMAN-draft changes, generated HTML changes,
source slot changes, previous-only and new-only original positions and uniquely
fingerprinted source movements. It refuses to infer a unique move when
multiple original sources share a digest. Source ordering is chosen by the
human and is **not** authenticated chronology. Disappearance is **not** a fix;
a new original position is **not** a verified new finding.

Input receipts must be byte-exact canonical
`lightup.private_lineage_receipt.v1` original outputs with literally false
authority/consent/identity/HUMAN GO fields, no duplicate keys and exactly
1–8 plausible original report digests. Inputs are owner-owned private 0600,
no symlink/hardlink aliases or parent-symlink traversal. Neither delta
artifact contains original SHA-256 values, report paths, target/client data,
original finding IDs or PRIVATE HUMAN notes. The output **remains PRIVATE**
because small ordinal/boolean differences may reveal sensitive work patterns.
Publishing refuses a nonempty destination; failure cleans up only its own
new files. `--verify-existing` strictly re-admits both original receipts,
demands exactly the expected two private outputs and compares reconstructed
file bytes without writing.

This comparison is an unsigned, local HUMAN continuity aid, not proof of
real original source authenticity, chronological progression, assessment,
consent, approval, remediation, security clearance, or release. No QA suite,
scanner or network is invoked. The existing source-owner, mandatory CI,
privacy/security review, separate current authenticated client/operator
consent with action-time revocation, and explicit HUMAN GO still gate release.

## Open the working product

Download [standalone.html](standalone.html) and open it locally. It is an actual single-file HTML application with its own static JavaScript and stylesheet SHA-256 pinned in the Content Security Policy, with all connections, images, external scripts, forms, frames and workers disabled. Alternatively open [index.html](index.html) alongside its sibling [app.js](app.js) and [style.css](style.css). The app does **not** run a backend, send telemetry or persist files/cookies/localStorage. Closing the tab forgets all private state.

1. Create/export an **original PRIVATE** \`lightup.lab_design_catalog.v1\` catalog using [Lab Scenario Studio, isolated PR #1595](https://github.com/Zennay/Lightup/pull/1595). This source includes actual private numeric lab targets and manually declared findings; the Lineage Desk deliberately discards targets, source finding identifiers and descriptions after admission. Only scenario ID membership and declared ground-truth *counts* are retained in memory for review. The Studio source and comparator may be on independent unmerged branches; there is no combined production integration.
2. Separately obtain 1–8 **already-completed** canonical cohort comparison JSON documents from the original, independent [assessment-runtime comparator PR #1515](https://github.com/Zennay/Lightup/pull/1515). This app never invokes the comparator, the original evaluation harness or a tool, and never creates results. Each source is <= 256 KiB; the private catalog is <= 1 MiB.
3. The Lineage Desk validates **exact** top-level/source schemas and four literal false authority fields; bounded duplicate-key-rejecting JSON decoding (including escaped aliases), finite metrics, original consistent regression flags, counter and score ranges, source case identities, matching metric baseline values in overlapping scenarios, and distinct candidate results. A malformed *batch* is rejected atomically; previously admitted originals and human casework remain intact. Source JSON is decoded with fatal UTF-8 handling and a leading UTF-8 BOM is rejected explicitly, so the original canonical representation cannot be silently normalized.
4. Compare each source's exact membership against the original scenario catalog. Missing or unexpected original source case(s) produce a prominent **HOLD**, without treating absence as remediation. Non-matching sources remain on-screen for PRIVATE human reconciliation, but **anonymous exports are disabled** until *all* source memberships exactly agree with the original catalog. The original catalog max is 32 scenarios; original comparator max is 64 cases.
5. Human workboard shows numbered local **Lab case 01…32**, unscored vs declared zero vs planted finding **declarations**, count of planted originals, each completed report's source-reported metric flags and local in-tab discussion stage. Declared finding information is **not detected-finding evidence**. A source-reported clean field is **not** proof of correct policy, permission or released production behavior.
6. When all source memberships match, export aggregate-only JSON, spreadsheet-safe machine CSV or standalone **script-free HTML** private human handoff. Aggregates have original anonymous counts and all false authorization/consent/dispatch/release fields. They **never** include original scenario IDs, host/IP/URL, declared finding identifiers, source filenames, original raw JSON, client identity, uploaded source hashes or local notes. Human stages are not real staff assignments.
7. **Explore invented demo** generates three fictional scenarios and two fictional completed reports entirely in memory for discovering the UI. Demo provenance is explicit in anonymous output and never presents source measurements as real. **Forget all local data** wipes original source and human stage state.

### PRIVATE native workroom source and destination safety

The optional `private_workroom.py` builder now requires every original catalog,
completed report and optional PRIVATE HUMAN draft to be an owner-owned,
**exact mode-0600 regular file with a single hard link**. It opens every parent
directory component without following symlinks, refuses symbolic-link aliases
and nonregular sources without blocking on a FIFO, bounds reads, and checks
the file identity/metadata before and after reading. All original source
bytes are admitted again immediately before publishing. A changed original
causes HOLD, not an outdated workroom.

Create an **existing, empty mode-0700 directory owned by the current user**
for the resulting PRIVATE HTML (for example `mkdir -m 700 /private/lineage-room`).
The output filename must be new and end in `.html`; publication uses
`O_EXCL|O_NOFOLLOW`, mode 0600, and a pinned non-symlink parent directory.
The builder does not create a public or anonymous export. Original source
files and source-owner authorization controls remain untouched. These
local checks are **not** proof of source authenticity, client consent,
human approval or production readiness.

### Human review workload and privacy-safe continuity

The private workboard now automatically ranks original **missing comparison case** HOLDs first, followed by source-reported scope/policy flags, findings/coverage, evidence/scoring, informational runtime/cost flags and no flagged source metric. Filter by flag family, original authored ground-truth mode (unscored / explicitly zero / planted) or local human discussion stage. The displayed row ordinal remains stable even when filtered or prioritized. **Confirm bulk stage for visible cases** asks human confirmation, changes only locally held human labels and supports one-step **Undo previous bulk change**. An individual stage change invalidates earlier bulk Undo. These are discussion labels only; no source results, claims, grants, staff assignments or permissions are modified.

**Private original fifteen-metric case inspector:** click **Inspect** on a source scenario ordinal (or select the ordinal directly) to view all 15 original comparison metrics across up to eight independent completed source slots, each original baseline, reported candidate number, numerical delta and *original* metric regression flag. Original case identifiers remain private even inside the table; only source ordinals are used. An absent case is shown as **ABSENT — HOLD**, not as zero, repaired or successful. The inspector runs no evaluation, accesses no targets and is not a verified outcome. Filtered/prioritized case rows can jump directly to the original metric inspector.

**Save PRIVATE source-bound human draft** (optional) exports *only* SHA-256 of original catalog raw bytes, ordered SHA-256 of each original imported completed comparison report, one local human stage per original lab scenario and four literal false authority flags. The browser does not store those hashes or stages anywhere automatically. **Restore an exact-source PRIVATE draft** requires *all* identical original file bytes, case membership and source order to have been reimported. An invalid or mismatched draft leaves current human work untouched. The implementation computes hashes with browser Web Crypto and fails gracefully if unavailable; it never sends source bytes, and never includes those hashes or source identities in the **anonymous** JSON/CSV/HTML exports. The private draft is sensitive correlation metadata and must not be shared as an anonymous artifact or relied on as source authenticity, consent or remediation evidence.

### Exact private source mismatch resolution without anonymized identity leakage

If an original designed scenario is absent in any finished original comparison, or the comparator has an extra original scenario unknown to the Studio catalog, the workspace stays **HOLD** and anonymous exports/print are unavailable. A new *private original mismatch panel* enumerates the affected original report slot and explains **catalog source missing from report** versus **unexpected completed report source**, without altering any original file or recommending a new run. Exact original scenario IDs are **hidden by default**, and appear only after the reviewer explicitly confirms **Reveal exact PRIVATE mismatch identifiers** on a trusted offline screen. This is human repair of source membership, not remediation or evidence about targets.

The original identifiers are held transiently in private browser memory only, rendered using textContent, never emitted to aggregate JSON/CSV/HTML or anonymous print, and re-hidden on replacement, append, removal, reordering, demo or Forget. The print stylesheet suppresses the private inspection section even if the IDs were deliberately revealed. Only source-matched original comparator data can be anonymously exported.

### One-click privacy-safe browser print

**Print anonymous brief** is enabled only after original lab catalog and completed report case memberships reconcile exactly and original canonical report admission succeeds. The screen and generated print view include only anonymous counts, source-reported priority category aggregates, stage totals and fixed HOLD/no-authority disclaimers. A separate print stylesheet hides the full private source, case queue, original 15-metric inspector, source selector, private notes and original source import controls from *all ordinary browser printing*, including Ctrl+P. If source membership differs, the printed page displays HOLD only. Saving a PRIVATE note does not change any public print, aggregate JSON, CSV or script-free HTML brief.

### Private proposed human follow-up — real workflow, no automatic action

The private case note editor keeps unsaved text as a **clearly marked in-memory scratch draft** when a human navigates among original cases. Scratch text does **not** enter the saved human draft, private HTML action dossier or anonymous exports until the user explicitly clicks **Save note**. Forget, replacing original catalogs and restoring saved source-bound private work discard scratch text. This prevents accidental case-navigation loss without silently recording unsigned drafts in handoffs.

For each original case, the human reviewer can propose a static **discussion group** (source owner, scope/policy, findings/coverage, evidence/scoring, operations, or unrouted) and **next human action** (verify original source, request original supporting evidence, discuss lab method, document human follow-up, or nothing recorded). Original source flags offer an optional suggested discussion route, never an employee identity, account permission or actual assignment. **Save PRIVATE human plan** is explicit; source records and scanner/runtime are not changed. These human labels are suggestions, not a certification or permission.

The existing private casebook now filters by proposed group and next action. **Suggest routes for visible unrouted cases** proposes source-based discussion routes across the *currently filtered* casebook only after confirmation, preserving already chosen routes and allowing one-step **Undo proposed routes**. A separate **Private human follow-up board** shows cases with a proposed next action, their source flag category, discussion route and current human stage; it can be filtered by stage/route and opens the original private fifteen-metric inspector for that case.

The PRIVATE exact-original-source-byte-bound workspace format has advanced to `lightup.assessment_lineage_private_draft.v3`. Alongside the existing private human notes and local stages, it now stores bounded enumerated proposed routes and human next actions in catalog ordinal order. The browser accepts older v1/v2 drafts and defaults missing proposed plans to unrouted/no action. Restoring any version is an atomic, local change only when the *same original catalog and original finished report bytes in the same human source order* are loaded; a mismatch retains existing work. On append/remove/replacement of original source, suggested routes/actions are discarded and stages reopened, while notes remain for explicit reconsideration. Human route Undo cannot roll back across an original source or draft transition.

**Owner-private action dossier:** After loading actual original files with SHA-256 byte binding, **Download PRIVATE human action dossier** exports a script-free static HTML packet with original case IDs, private file hashes, private notes, proposed discussion route/action, source-reported priority and human stage. This is an explicitly confirmed **sensitive PRIVATE** handoff, not an anonymous handoff. It is marked HOLD even when original case membership lines up and includes no scanner commands, target IPs, credentials, authorization or actionable access grants. Never upload, share or print it as an anonymous report. Existing aggregate-only JSON/CSV/HTML and the browser anonymous print are separate; they receive only fixed-route/action **counts**, never the original IDs, notes or source hashes.

### Original-source human priority dashboard and anonymous casework brief

The private review workboard now shows six navigable **human source-priority cards**: missing original scenario in a completed source, original scope/policy flags, findings/coverage flags, evidence/scoring flags, informational operations, and original reports with no flagged metric. These are strictly **read-only source classifications**, not independently measured severity, release eligibility or authenticated review. Each card shows anonymous source scenario counts and how many local human discussion stages remain unreviewed/in discussion/documented; click a card to filter existing human case rows, never to run a scan. The "no original source flags" filter is not a PASS classification.

When original scenario membership matches exactly, anonymous aggregate JSON now includes **human_queue_priorities** with category keys, anonymous counts and fixed stage totals only; the existing aggregate CSV and script-free handoff HTML display the same category totals. Neither a private note nor original scenario/host/finding identity, source file name/hash or raw source appears in these public outputs. Source-mismatched workspaces HOLD every aggregate download.

### Expanded original-source and human review workflow

**Source ordering:** use the in-memory original report selector to move an already imported original source slot earlier/later, or explicitly remove a report from the current workspace (original file remains untouched). Order is a **human display preference, never authenticated chronology**. The original file-byte SHA256 sequence is kept in the same new human order for PRIVATE draft exports, preventing accidental restore against a differently ordered set. When a source is appended or removed, ALL local human-stage labels are reopened to \`needs_review\` (because old human conclusions may be stale against a different source set); manually entered PRIVATE notes are retained only in memory for the human to reconsider. Reordering alone does not change evidence and does not reopen human stages.

**PRIVATE per-case human notes:** from the fifteen-metric inspector choose a private lab case and explicitly save up to 400 characters of local human review text. It is not measured evidence, proof of remediation, an authenticated reviewer identity or a permission. It is never rendered via untrusted HTML or included in aggregate JSON/CSV, printed brief or unsigned public summaries. The optional *PRIVATE* source-byte-bound work draft initially used \`lightup.assessment_lineage_private_draft.v2\` (retained for backward compatibility): exact original source-byte SHA256 fingerprints, human-stage array and **PRIVATE note array** in original scenario order. Restore is atomic only after all exact sources are present; the original stage-only v1 draft remains readable with empty notes. If the original files differ, no stage or note is replaced.

**One-file PRIVATE workroom:** if you need to open original files together, run \`private_workroom.py\` with the existing catalog and completed cohort reports. The produced HTML contains sensitive original source bytes as inert base64, preserved only in an owner-only \`0600\` file. Opening the file *does not admit sources* until the operator clicks the dedicated button. On successful import, template content is cleared from the active DOM, with the original raw-byte hashes still independently used for source-bound PRIVATE drafts; this does not remove the sensitive original from disk. There is no network, auto-run or permission.

### Portable PRIVATE source + human-review continuity

The owner-private `private_workroom.py` builder now accepts an optional `--human-draft` argument containing a *previously saved* original-byte-bound human work draft v1/v2/v3 (up to 65,536 bytes). This creates a **single owner-private HTML file** carrying exact original catalogue bytes, existing completed comparator reports and, if explicitly supplied, human stages, private notes and proposed discussion plans. All input files, including the human draft, must be owner-owned regular `0600` files. The builder refuses duplicate input file paths, original-byte mismatches, bad statuses/authority flags, invalid human fields, oversized content and a pre-existing output path. Original SHA-256 fingerprints and report *human order* are checked before packaging; any mismatch fails closed and no output is produced. It does not authenticate measurement claims or authorize a scan.

```bash
python3 assessment-lineage/private_workroom.py \
  --catalog /private/original-lab-catalog.json \
  --report /private/completed-cohort-01.json \
  --report /private/completed-cohort-02.json \
  --human-draft /private/lightup-PRIVATE-lineage-human-draft.json \
  --output /private/lightup-PRIVATE-full-review-workroom.html
```

The local browser requires **two separate explicit actions**. First, **Load embedded PRIVATE originals** admits all source records using the unchanged canonical source checks and then wipes the inert original-source HTML template from the active DOM. Second, **Separately restore exact-source PRIVATE human work** verifies the original byte fingerprints once more and then restores human stages, notes and proposed plans; neither is automatic. If the original sources change or are reordered, the pending embedded draft is invalidated. **Forget all local data** also clears un-imported inert private source text and any pending human draft from the active browser document, although the sensitive HTML file on disk is **not** deleted. Both the public standalone and all anonymous reports contain **no original source or embedded human draft**.

### One PRIVATE self-contained workroom from genuine existing lab source files

This workflow does **not** create a lab run. To avoid manually selecting the same sources every time, [private_workroom.py](private_workroom.py) makes a second, deliberately sensitive, standalone HTML file containing only **your own original existing** Lab Scenario Studio private JSON and 1–8 completed original comparator cohort reports. It embeds raw JSON bytes **only as inert base64 in an HTML template**, never as active script or a network payload. The existing standalone app checks and admits the original JSON *after an operator explicitly clicks* **Load embedded PRIVATE originals**. Incomplete, duplicated, contradictory or incompatible source packs produce HOLD and preserve any already open browser workspace.

Inputs **must** be regular owner-owned files with mode \`0600\` (no group/other access, no symlinks); each private catalog is <=1 MiB and each original finished report <=256 KiB. Example, after downloading the branch's \`standalone.html\` plus \`private_workroom.py\` into one private directory:

\`\`\`bash
python3 assessment-lineage/private_workroom.py \
  --catalog /private/lab-original.json \
  --report /private/original-cohort-A.json \
  --report /private/original-cohort-B.json \
  --output /private/lightup-PRIVATE-workroom.html
\`\`\`

The output **must not already exist**. Creation uses exclusive O_EXCL mode \`0600\`, owner-only files and current checked-in static standalone JS/CSS SHA256 pins, never a user-supplied HTML template. The new PRIVATE HTML contains sensitive source byte strings: store it separately and **never share or upload** it, unlike aggregate-only anonymous exports. No network requests, dynamic imports, credentials, database access, shell invocation, tool/scanner execution or CI run is done by this helper.

When opened, the browser still displays the no-authority original source import boundary; nothing runs or auto-loads. Click **Load embedded PRIVATE originals** to atomically admit exactly the original source catalog and reports. Only source identities and declared ground-truth counts remain in memory after admission, not original IPs, descriptions or finding IDs. The original byte-bound private stage resume continues to work if browser crypto is available, because the in-memory source SHA-256 corresponds to the exact embedded original bytes. Template text is cleared after successful admission. A copied PRIVATE HTML is still a copy of original sensitive sources even after browser memory clears it; deleting the original file requires separate human action.

The standalone public checked-in version carries **no original source bundle**. Browser previews through GitHub's own file renderer are not a live deployed app; download the HTML files and open on a trusted offline workstation. Both original source modules are separate unmerged DRAFT branches and are not asserted to be production-integrated.

### Source boundary and standalone build

Only these new isolated paths are owned: \`assessment-lineage/{app.js,index.html,style.css,standalone.html,build_standalone.py,private_workroom.py,README.md}\`. No modifications to original labeval, labrunner, auth/domain/grant/consent, original assessment PRs, scanner/handler, tests/QA or CI workflows. Build reproducibly with the Python standard library: \`python3 assessment-lineage/build_standalone.py\`. Inspection may use Node syntax check only; do not write or run a QA/regression suite under 17 October policy.

Files are untrusted and **not authenticated**, even if source format matches. Original source exact-head hosted and permanently registered named VPS CI, independent security/privacy review, real separate authenticated client and operator consent with action-time revocation, original authorization issue source fixes and explicit human GO all remain necessary before *any* merge, deployment or active target behavior. This isolated draft offers **no** such permission. No branch merge or production deployment is implied by GitHub “mergeable”.

## Multi-snapshot PRIVATE receipt history (2–12)

The native `receipt_history.py` extends the two-receipt comparison into one
bounded history of **2–12 original canonical PRIVATE source receipts** from
`private_workroom.py --private-receipt`. It reports each snapshot and every
adjacent transition, including catalog/HUMAN-draft/workroom byte-change flags,
source membership additions/absences, ambiguous duplicate fingerprints, and
the selected report-slot movement when both adjacent snapshots have unique
fingerprints. It distinguishes sources first seen anywhere in the selected
sequence from a source that reappears after being absent in an intervening
snapshot. The source-presence matrix now identifies each reappearance slot,
the longest consecutive presence streak and the longest gap between appearances;
the CSV carries the same per-slot fields for filtering and handoff. These labels
describe only the operator-selected sequence, never authenticated chronology
or the reason for absence.

```bash
umask 077
mkdir -m 700 /private/lineage-history
python3 assessment-lineage/receipt_history.py \
  --output-dir /private/lineage-history \
  /private/snapshot-01/review.private-lineage-receipt.json \
  /private/snapshot-02/review.private-lineage-receipt.json \
  /private/snapshot-03/review.private-lineage-receipt.json
```

For repeatable command lines and safer manual ordering, the same tool also
accepts a separate `--receipts-file` instead of positional paths. The list
must be an owner-private mode-0600 regular file with one canonical absolute
receipt path per LF-terminated line (2–12 lines, no duplicate paths, controls,
bidi marks or disguised line breaks). The exact selection-list bytes and
ordering are re-admitted immediately before publication and read-only reopen;
the list itself is never copied into the output packet.

```bash
umask 077
cat > /private/lineage-history-selection.txt <<'EOF'
/private/snapshot-01/review.private-lineage-receipt.json
/private/snapshot-02/review.private-lineage-receipt.json
/private/snapshot-03/review.private-lineage-receipt.json
EOF
chmod 600 /private/lineage-history-selection.txt
python3 assessment-lineage/receipt_history.py \
  --receipts-file /private/lineage-history-selection.txt \
  --output-dir /private/lineage-history
```

The receipts must be distinct, canonical, owner-private mode-0600 regular
files; the output directory must already exist, be owned by the current user,
have exact mode 0700, and be outside every input directory. The output is a
three-file packet: scriptless HTML, JSON and flat CSV. Files are exclusive
0600 outputs; existing files are never overwritten. To verify a saved packet
without writing, use the same ordered receipt list and add
`--verify-existing`. Reordering receipts intentionally changes the result;
the order is human-selected, not authenticated chronology.

Full receipt/source hashes, source paths, raw source content, case IDs and
private notes are omitted from the report. Packet-local labels still reveal
correlation patterns and are **not anonymization**. Duplicate fingerprints
make slot movement ambiguous; a source absent from a later snapshot is not
proof of deletion, remediation, revocation or clearance. The tool reads only
the receipt files, not the original lab/catalog/report files described by
them, and invokes no comparator, scanner, target, network or external service.
All consent, authorization and HUMAN GO flags remain false. This is a private
review aid, not a source-authenticity or release certificate.

## Portable native PRIVATE receipt-history kit

Build the self-contained standard-library CLI package from the repository root:

```bash
python3 assessment-lineage/build_offline_kit.py
```

This deterministically rebuilds `assessment-lineage/LightUp-Private-Receipt-History-Kit.zip`
and its `.sha256` sidecar. The ZIP contains only the history/comparison source,
shared private reader, README and operator instructions; it never packages a lab
receipt, catalog, report, finding, target, client file or HUMAN note. `HASHES.txt`
contains unsigned file-integrity digests for the kit contents; the sidecar hashes
the ZIP. Neither proves authorship, consent, identity, measurement validity or
release authority.

After extracting the kit, run `python3 receipt_history.py --help` for the local
CLI. Inputs remain original owner-private canonical receipts; the output is a
separate owner-owned exact-mode-0700 directory and the three generated files are
exclusive mode-0600 private artifacts. See
[START-HERE-RECEIPT-HISTORY.txt](./START-HERE-RECEIPT-HISTORY.txt) for the
portable quick start and boundaries.

## Private data handling

The original source catalog is sensitive. Local file selection does not upload it, and the standalone does not send it to any server; downloaded aggregate handoffs avoid source identities but do not prove provenance. Use suitable private device storage, and independently review any source before ingestion. Private scenario IDs exist transiently in memory only to match against original source cases and are not displayed to an external audience. Anonymous **HOLD** means a human must reconcile genuine source evidence, not repeat the execution automatically.


### Offline source-byte binding

The private HUMAN draft uses Web Crypto when available and a portable local SHA-256 fallback when `crypto.subtle` is unavailable in a `file://` browser context. This keeps exact-byte-bound review drafts usable offline. Digests are unsigned local consistency values, not authenticated source provenance, consent, authorization or release approval.


### Latest local action wins for private source intake

All asynchronous imports of the original PRIVATE Studio catalog, complete cohort reports, encrypted-workroom-free embedded PRIVATE original bundle and source-bound HUMAN review drafts are now generation-scoped. A newer file selection, Forget, fictional demo, a HUMAN stage/route/note edit, or a source display reorder/removal makes pending older file reads stale. Stale completions cannot publish an old source or restore earlier HUMAN planning after the operator's newer decision. The entire original file bundle still validates atomically before mutation; invalid or superseded inputs leave the existing private workroom untouched. Source hashes are local, unsigned byte binding only: no source authenticity, client consent or authorization is inferred.
