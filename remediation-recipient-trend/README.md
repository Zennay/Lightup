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
