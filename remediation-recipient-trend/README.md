# LightUp · Private Recipient HUMAN Workload Comparison

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** A complete new-only offline follow-on to the existing [source-free HUMAN Evidence Cockpit owner PR #1661](https://github.com/Zennay/Lightup/pull/1661), built on that original branch without altering its files or existing claims.

## Actual product workflow

A receiving operator who has **two previously delivered source-free, complete Cockpit folders** can now compare their *aggregate HUMAN workload* locally without asking the source owner to release client records, original evidence, source hashes, free-text notes or finding identifiers. This was not possible with the original `compare_workrooms.py`: that private source-owner tool needs the complete original workrooms, not the portable source-free receiver handoffs.

The comparison:

1. Reuses the original `read_cockpit.inspect` for **each complete received folder**. This admits original owner-only 0700/0600 files, exact manifest, duplicate-key-safe canonical JSON, source-free schema, native exact HTML reconstruction, warnings and false-only authority flags. Both inputs must be entirely valid.
2. Builds left/right counts and signed right-minus-left differences for HUMAN question totals, pending counts, local stage totals, HUMAN follow-up reason occurrences and aggregate reuse/attachment attention. No row-by-row source joins; it cannot match clients, findings, source owners or cases.
3. Re-admits both entire received originals again before publishing and rejects changed source-free bytes. Produces **one new, exclusive, atomic** owner-private 0700 directory with `index.html` (accessible, scriptless offline native HTML/CSP), `counts.json`, `counts.csv`, a separate `recipient-actions.md` with **only locally counted human follow-up reason prompts** (prioritised by increasing reason occurrences), and a canonical unsigned manifest. Output files are original native 0600 private files.
4. Provides a separate native **read-only reopen**: `receive.py` independently rechecks the receipt folder, strict schema, exact integer-only signed-delta arithmetic (bool/float rejected), manifest checksums and *byte-identical reconstruction* of the HTML, JSON, CSV and generated private HUMAN follow-up Markdown. It requires **no original cockpit folders** after comparison. Neither operation writes to any input or sends anything.

### Prepare on an owner-controlled offline Linux machine

Obtain two *complete, separate, private* canonical source-free HUMAN Cockpits. These can be the original local `cockpit/` directories or previously transferred complete folders from `handoff.py`. Each input must already be an existing private 0700 folder and contain nothing beyond the native allowed source-free artifacts. On the receiving machine, first run the existing native original command for either source:

```sh
python3 remediation-evidence-bundle-integrity/read_cockpit.py \
  --cockpit "$HOME/lightup-private/received-left"
python3 remediation-evidence-bundle-integrity/read_cockpit.py \
  --cockpit "$HOME/lightup-private/received-right"
```

The original read-only admission returns **exit code 2 for REVIEW_ONLY** and **3 for HOLD**. Never treat exit 2 as authorization or security clearance.

Choose an unused output name inside an **existing private 0700 directory**:

```sh
python3 remediation-recipient-trend/trend.py \
  --left "$HOME/lightup-private/received-left" \
  --right "$HOME/lightup-private/received-right" \
  --output-dir "$HOME/lightup-private/recipient-comparison-001"
```

Open `recipient-comparison-001/index.html` **locally**, or use `counts.csv` for an internal workload discussion. This is a *human-only summary* that must remain private despite containing no original IDs.

To check **the generated comparison itself**, on the original or a separate private recipient machine with this code installed:

```sh
python3 remediation-recipient-trend/receive.py \
  --receipt "$HOME/lightup-private/recipient-comparison-001"
```

Both commands return **2 (REVIEW_ONLY)** on local consistency and **3 (HOLD)** on any invalid input or output, not zero. No CLI automatically transfers or uploads anything.

## Deliberate interpretation limits

- The left/right order is chosen by the operator; it is **not signed or authenticated chronology**.
- Equal slot counts **do not** establish the same original source cohort. Different slots may contain duplicate clients/cases; totals are workloads per slot, not unique findings. **No per-case or per-slot alignment is inferred.**
- Reasons are occurrence counts: a HUMAN question may carry more than one reason. Signed deltas represent arithmetic, not independently verified state changes.
- Even a lower pending count, a higher `answered_human` count, fewer link/reuse notices or a valid local manifest **never proves a security fix, authorized retest, evidence authenticity, risk reduction, grant, client consent or owner acceptance**.
- The report's local SHA-256 manifest is **not a signature**, not proof of who produced either original, and cannot independently prove source data provenance. A malicious person controlling the entire unsigned packet can forge consistent aggregates.
- The user should ask the original authorized owner to reconcile cohort membership and to separately validate genuine evidence/remediation and any authenticated consent through existing source-owner processes.

No model, remote URL, target interaction, scan, grant, issue of remediation execution, writeback to Casework, browser external asset, network transmission, secrets, user authentication change, existing tests/QA/CI or source-owner file modifications.

## Release and integration

The companion stays separate and **DRAFT/HOLD**, stacked on original #1661; it does not claim its parent is released. Do not merge into `main` or deploy until all **original** exact-head hosted plus permanently registered named VPS CI, source-owner and independent security/privacy/browser review, #177/#182/#829, separately authenticated *current* client/operator consent with at-use revocation when actually required, and explicit HUMAN GO are met. No gate is bypassed, no extra gate is introduced.


## Multi-moment PRIVATE recipient workload studio (2–12 handoffs)

The new `recipient_workload_series.py` accepts **2–12 completely received original source-free cockpit folders**. Each complete input is independently admitted via the **existing native** `read_cockpit.inspect` (owner/private file modes, exact original manifest, original native schema and HTML reconstruction). Exact duplicate incoming complete packets are rejected rather than pretending another revision. Original packet bytes are re-admitted before the new output is published.

The generated entirely OFFLINE private `index.html` is a navigable scriptless HTML dashboard with a native accessible pending-workload progress view for every operator-selected packet, and adjacent count-only deltas. It includes a current-count HUMAN reason brief, not source data. The newly published PRIVATE directory contains canonical `series.json`, `series.csv`, original-owned `human-followup.md` discussion prompts and its own unsigned SHA-256 manifest. Neither original client/finding IDs, source hashes, evidence, free-text case notes nor confidential original file paths are included. Owner-only 0700/0600 permissions, exclusive no-overwrite atomic directory publication and zero network activity continue to apply.

Use **one native receiver operator command** for the entire new product, always choosing an unused destination inside an existing private 0700 folder:

```sh
python3 remediation-recipient-trend/receiver_desk.py series \
  --cockpit "$HOME/lightup-private/received-01" \
  --cockpit "$HOME/lightup-private/received-02" \
  --cockpit "$HOME/lightup-private/received-03" \
  --output-dir "$HOME/lightup-private/recipient-series-001"
```

The standalone `recipient_workload_series.py` CLI accepts identical `--cockpit` and `--output-dir` parameters. On a receiving machine that no longer has these original source-free packets, **independently re-open the entire private report**:

```sh
python3 remediation-recipient-trend/receiver_desk.py reopen-series \
  --receipt "$HOME/lightup-private/recipient-series-001"
```

The standalone `timeline_receive.py` accepts `--receipt` as well. It reconstructs HTML, CSV, JSON and HUMAN follow-up text byte-for-byte, enforces exact schema and nonnegative original aggregate counts, exact integer-only signed per-ordinal differences, original false-only authority flags and the full 0700/0600 inventory. No original source, client account, evidence, consent or target is contacted, and no action is sent back to any source system.

For simple two-snapshot comparisons the equivalent unified commands are:

```sh
python3 remediation-recipient-trend/receiver_desk.py compare \
  --left "$HOME/lightup-private/received-01" \
  --right "$HOME/lightup-private/received-02" \
  --output-dir "$HOME/lightup-private/two-moment-review-001"

python3 remediation-recipient-trend/receiver_desk.py reopen-compare \
  --receipt "$HOME/lightup-private/two-moment-review-001"
```

**Important interpretation:** packet ordinals are a HUMAN-selected order, not authenticated timestamps. Original source/client case membership across handoffs is unknowable in the source-free recipient packets. A rising/falling total cannot be labeled a security improvement, new vulnerability, verified remediation or clinical/contractual SLA. Local checksums never authenticate the original producer. The recipient must contact the authenticated original private source owner for actual evidence, retest, client/operator consent and any real activation decisions.

Every successful command returns exit **2 / REVIEW_ONLY**; invalid or unsafe packets return **3 / HOLD**. No QA suites or release gates are modified. Do not treat these values as green CI.

The integrated CLI is deliberately named `receiver_desk.py`, **not** `operator.py`: Python imports its own standard `operator` module during startup, and a sibling `operator.py` would shadow it and prevent the actual installed CLI from loading.

## Full PRIVATE editable HUMAN follow-up workroom — offline source-bound workflow

The original comparison/series reports offer source-free aggregate snapshots. A receiving HUMAN reviewer also needs a real local **editable, saveable, resumable and source-bound** follow-up workspace, without editing source-owner records or leaking client identities.

New `recipient_studio.py` / `recipient_studio.js` and `recipient_journal.py` / `recipient_journal_receive.py` complete this workflow. The unified native `receiver_desk.py` exposes them as `human-studio`, `human-publish`, `human-reopen`. All product files stay within this independent owned directory, with no original evidence/Casework/CI/source-owner modifications. Original source-free comparison/series producer and native receipt validators are **reused unchanged**.

### 1. Create a private offline interactive workroom

Starting with a **complete** already generated native PRIVATE comparison or multi-packet series receipt (not a hand-written JSON excerpt):

```sh
python3 remediation-recipient-trend/receiver_desk.py human-studio \
  --receipt "$HOME/lightup-private/recipient-series-001" \
  --kind series \
  --output-dir "$HOME/lightup-private/human-studio-001"
```

For a two-cockpit comparison, use `--kind compare` and provide its original private comparison receipt. The original exact native `receive.inspect` or `timeline_receive.inspect` re-admits the **whole original receipt**, including private 0700/0600 provenance, original source-free schema, all file checksums and byte-identical output reconstruction. No substituted/unknown client record is admitted by our workflow.

The new **atomic PRIVATE** `human-studio-001/` folder has native 0600 `index.html`, `source-free.json` and SHA-256 `manifest.json`, each under an exclusively published 0700 output directory. The HTML is fully portable and self-contained, with CSP-pinned inline CSS/JS, no scripts or assets fetched, no browser storage, analytics, authentication, remote provider, grant, scanner, target or active assessment.

Open `index.html` locally in a trusted browser. For every **aggregate original HUMAN reason category**:

- See current original source-free reason occurrence totals and the previous selected snapshot's arithmetic difference, plus the original unchanged native source-owner follow-up wording.
- Set *only local HUMAN bookkeeping*: `open`, `in_review`, `waiting_source_owner`, `answered_human`.
- Choose a **proposed HUMAN** route: `unassigned`, `source_owner`, `human_reviewer` or `privacy_reviewer`. These are advisory selections, **not assignments or approvals**.
- Write up to 800 UTF-16 characters / 1,200 UTF-8 bytes of PRIVATE local text. Avoid entering actual customer identifiers, target information, evidence bytes, credentials or secrets.
- Explicitly download a PRIVATE JSON journal; later re-import it into this browser using the file selector only when bound to the **same exact original source-free receipt byte fingerprint**. Import never writes partial rows. Reset requires confirmation.

Journal import within the browser is advisory and cannot cryptographically authenticate a source; the next **native Python ingestion** is the definitive strict local schema/binding check. No browser `localStorage`, indexedDB, cookies, automatic file overwrite, online service or hidden background save exists.

### 2. Publish the saved local HUMAN journal as a separate private handoff

The browser typically downloads files with ordinary OS permissions. Because the journal can contain HUMAN notes, **first** copy it to an existing trusted owner-private 0700 folder as 0600 rather than passing an unrestricted Downloads file into the protected source boundary:

```sh
install -d -m 700 "$HOME/lightup-private/human-intake"
install -m 600 "$HOME/Downloads/lightup-PRIVATE-HUMAN-journal.json" \
  "$HOME/lightup-private/human-intake/review-001.json"

python3 remediation-recipient-trend/receiver_desk.py human-publish \
  --receipt "$HOME/lightup-private/recipient-series-001" \
  --kind series \
  --journal "$HOME/lightup-private/human-intake/review-001.json" \
  --output-dir "$HOME/lightup-private/human-review-001"
```

The original **complete source-free receipt** is natively admitted again, before and immediately prior to publication. The HUMAN journal is read as one canonical bounded owner-private no-follow file with duplicate JSON keys rejected, exact original reason/count/delta/ordinal identity, no fabricated authority flags, fixed source byte fingerprint, fixed HUMAN stage/route enums, bounded Unicode-safe local notes and no partial acceptance. The new output includes only `journal.json`, a scriptless **private-review.html** with escaped HUMAN text, and a separate **anonymous-counts.json** containing only grouped stage/route totals (no notes, original IDs or source hash). Its SHA256 manifest is a **local unsigned checksum receipt**, never proof of who authored the source.

The generated source-rich `private-review.html` and `journal.json` are owner-private; `anonymous-counts.json` must also remain private where low-volume workload could identify a client or team. No source-owner Casework, finding status, grant, consent, scan or retest is modified or sent.

### 3. Safely reopen the published private HUMAN report without originals

```sh
python3 remediation-recipient-trend/receiver_desk.py human-reopen \
  --folder "$HOME/lightup-private/human-review-001"
```

The separate receiver checks the exact private folder inventory, original valid-human reason categories, literal non-authorizing flags and count/delta/notes grammar; then **reconstructs the complete HTML and both JSON products byte-for-byte** against the native deterministic renderer and all manifest file SHA256. It does **not** need source/customer/evidence bytes or the original source-free snapshot. As with all checksum-only offline receipts, self-consistency does not establish trust in the author, real client permission, a security fix or actual original case membership.

**All CLI commands intentionally return exit 2 (REVIEW_ONLY)** on an accepted local human-only operation and **3 (HOLD)** on invalid source or private output; never treat either as a security authorization, a green CI check or a verified remediation. This additional product remains **DRAFT/HOLD** until original exact-head hosted and named permanent VPS CI, original source-owner, independent privacy/security/browser review, existing #177/#182/#829, genuine separately authenticated current client/operator consent with action-time revocation where relevant, and explicit HUMAN GO.

## Before opening a received editable HUMAN Studio, verify its complete local product

```sh
python3 remediation-recipient-trend/receiver_desk.py human-open-studio \
  --folder "$HOME/lightup-private/human-studio-001"
```

This original `recipient_studio_receive.py` independently admits exactly the three trusted owner-private 0600 studio files, a canonical false-authority manifest, the expected original reason categories and literal original native human follow-up wording; it reconstructs the entire CSP-pinned HTML and source-free seed byte-for-byte from the trusted code. It does **not** prove a sender's authenticity or a customer's consent. Exit 2 means only internal local byte/render consistency, never a security PASS.

## Compare TWO saved PRIVATE HUMAN journal revisions on the exact same report

For a genuine PRIVATE HUMAN progress workflow (not security remediation), first make two separately published `human-publish` directories, created from *the same unchanged original compare/series source-free receipt*, but different private HUMAN stages/routes/notes. Then compare their original complete readmission, without revealing PRIVATE note bodies:

```sh
python3 remediation-recipient-trend/receiver_desk.py human-diff \
  --before "$HOME/lightup-private/human-review-001" \
  --after "$HOME/lightup-private/human-review-002" \
  --output-dir "$HOME/lightup-private/human-revision-001"
```

The native `recipient_journal_history.py` first independently re-admits BOTH original HUMAN follow-up directories via the unchanged current `recipient_journal_receive.inspect`, checks that the journals have the **exact same recorded original source-free report SHA**, identical canonical reason membership, counts and original arithmetic deltas, and rejects unchanged duplicate journals. Neither original source, previous notes, customer identity nor original case records are altered.

The output is an **atomic PRIVATE** 0700 folder containing `index.html` and `private-changes.csv` showing only fixed HUMAN reason codes, before/after stages and proposed routing plus a **note-changed boolean** (never note text). A matching private `summary.json`, separate `anonymous-counts.json` containing only group change totals, and canonical SHA-256 manifest complete the local dossier. This does not reconstruct which customer issues changed or whether any finding was fixed.

After the original journals are no longer present, independently reopen the private comparison receipt:

```sh
python3 remediation-recipient-trend/receiver_desk.py human-reopen-diff \
  --folder "$HOME/lightup-private/human-revision-001"
```

This can reconstruct the private HTML, CSV, JSON and anonymous counts byte-for-byte from the locally admitted changed HUMAN records, and validate the complete original owner-private file inventory. Reopening only proves self-consistent local bytes, not an authenticated source identity, reliable chronology, real assignment, scan authorization, active remediation or an approved retest.

Everything above is offline, HUMAN-only and PRIVATE; do not attach downloaded notes or small-group workload exports to GitHub, Notion, CI, shared drives or public issue comments. Original-release gates remain unchanged.


## Strict PRIVATE HUMAN journal restore

The browser workroom now admits only the exact canonical UTF-8 JSON representation emitted by its own journal exporter: fatal UTF-8 decoding, no leading BOM, exact pretty-printed JSON bytes with one terminal newline, then the existing schema/source-snapshot checks. Duplicate-key JSON and alternate whitespace/key-order encodings are rejected before any HUMAN entry is applied. Failed admission leaves all current HUMAN entries unchanged. This protects the local review format; it does not authenticate a sender, reviewer identity, source producer, client consent or remediation.
