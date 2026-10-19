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

The new `timeline.py` accepts **2–12 completely received original source-free cockpit folders**. Each complete input is independently admitted via the **existing native** `read_cockpit.inspect` (owner/private file modes, exact original manifest, original native schema and HTML reconstruction). Exact duplicate incoming complete packets are rejected rather than pretending another revision. Original packet bytes are re-admitted before the new output is published.

The generated entirely OFFLINE private `index.html` is a navigable scriptless HTML dashboard with a native accessible pending-workload progress view for every operator-selected packet, and adjacent count-only deltas. It includes a current-count HUMAN reason brief, not source data. The newly published PRIVATE directory contains canonical `series.json`, `series.csv`, original-owned `human-followup.md` discussion prompts and its own unsigned SHA-256 manifest. Neither original client/finding IDs, source hashes, evidence, free-text case notes nor confidential original file paths are included. Owner-only 0700/0600 permissions, exclusive no-overwrite atomic directory publication and zero network activity continue to apply.

Use **one native receiver operator command** for the entire new product, always choosing an unused destination inside an existing private 0700 folder:

```sh
python3 remediation-recipient-trend/receiver_desk.py series \
  --cockpit "$HOME/lightup-private/received-01" \
  --cockpit "$HOME/lightup-private/received-02" \
  --cockpit "$HOME/lightup-private/received-03" \
  --output-dir "$HOME/lightup-private/recipient-series-001"
```

The standalone `timeline.py` CLI accepts identical `--cockpit` and `--output-dir` parameters. On a receiving machine that no longer has these original source-free packets, **independently re-open the entire private report**:

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
