# LightUp · PRIVATE Assessment Briefing & Source Drift

**INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Independent new-only source in `assessment-briefing/` built for original, **already-produced**, strictly isolated lab-assessment JSON from original held assessment-runtime [#1608 / PR #1610](https://github.com/Zennay/Lightup/pull/1610). Companion to original offline review issue [#1637](https://github.com/Zennay/Lightup/issues/1637) without changing that actively owned original desk [PR #1639](https://github.com/Zennay/Lightup/pull/1639), original lab tool, authorization or scan surfaces.

## Usable offline product

From a trusted local checkout containing a PRIVATE original source JSON produced elsewhere:

```bash
python3 assessment-briefing/briefing.py --source ./original-private-lab.json --output-dir ./NEW-PRIVATE-BRIEFING
```

This **does not run a scan**. Creates the new directory exclusively as 0700 and the following files as 0600, refuses to overwrite existing output, and rejects symlinks, duplicate JSON keys and unsupported/oversize source before publishing:

- **`private-briefing.html`:** Print-friendly scriptless, CSP-hash-pinned offline report with original severity distribution, finding descriptions, check/capability, exact declared endpoint ordinal when literally equal, private source evidence reference counts, impact/fix/retest/evidence summary in opt-in expandable details, and blank HUMAN-only follow-up worksheets. Records appear in source order. Empty original results still produce a report.
- **`human-followup.csv`:** Blank HUMAN ownership / action / blocker worksheet indexed only by original row ordinal, source severity and evidence-reference count. No source target URLs, findings text, names, hashes or evidence content in this CSV; still treat aggregates as PRIVATE. Blank cells cannot inject spreadsheet formulas.
- **`manifest.json`:** Original source byte SHA-256 (unsigned), output file SHA-256, source-reported totals and literal `false` authentication/authorization/release declarations. Not a signed receipt.

To review literal source drift between **two separately, already-produced** original lab results:

```bash
python3 assessment-briefing/compare.py --before ./source-A.json --after ./source-B.json --output-dir ./NEW-PRIVATE-DRIFT
```

The comparator requires a different source-byte SHA, different run ID, identical original scenario literal and same exact declared target **set**. It groups only by exact source target + original capability ID + original check ID. Duplicate keys on either side remain **AMBIGUOUS** (no silent pairing). Other source-declaration categories are `reported_only_before`, `reported_only_after`, `source_description_changed` and `source_description_equal`. This is a textual source-reconciliation heuristic only — **neither absence nor change proves a fixed, new, active, vulnerable or retested target**.

The second packet contains:

- **`private-drift.html`:** Fully offline scriptless printable category dashboard and PRIVATE before/after original source descriptions, plus blank human evidence and follow-up worksheets. Original identifiers and declared target strings are shown only in this PRIVATE HTML.
- **`human-drift-followup.csv`:** Group ordinal, category, original declaration counts and blank HUMAN fields, without target/ID/finding literals.
- **`manifest.json`:** Unsigned original source fingerprints, category counts, PRIVATE output digests and literal-false permission flags.

### Explicit safety model

Both CLIs read only explicit ordinary local files (at most 8 MiB), cap original findings at 2048, endpoints at 16, validate exact frozen original field shapes, basic metric consistency and original lab context if `benchmark_case` exists, reject ambiguous JSON object keys and fail closed with content-free error messages. These are **conservative presentation checks, not original-source authentication or full independent correctness proof**. The original source is unchanged.

Both output directories are **new only**; on failure, newly published files are removed and no old output is overwritten. Successful preparation intentionally exits with code **2 (REVIEW_ONLY)**; HOLD returns **3**. Nothing contacts a target, resolves DNS, loads a browser resource, writes a credential, runs a model, grants permission, claims a vulnerability verdict or changes existing original results. Source signatures, source trust, assessments, actual client/operator identity, grant/revocation and security verification are **not** established by a hash or this report.

The printable HTML and any exported files are **PRIVATE** even if the CSV omits original identifiers. Never upload original reports or private HTML/manifest publicly. Device, browser and human review-channel controls remain the operator's responsibility.

## Delivery isolation and release gates

This branch adds only `assessment-briefing/`. No existing source-owner, parallel PR, default webapp, original DomainStore, CLI entrypoint, execution policy, scan worker, security gate, CI, tests or deployment file is modified. No new QA or regression suites were authored or run.

The source stays **DRAFT/HOLD**. No merge to `main`, deployment or live target use without the original exact-head hosted and permanent named VPS CI gates, source-owner sign-off, independent privacy/security review, original #177/#182/#829 closure, actual separately authenticated client/operator consent including at-use revocation, and explicit HUMAN GO. This module cannot satisfy any of those requirements.

## New: privacy-minimal human briefing (without original source identifiers)

For a separate private human conversation that should **not** include original target URLs, finding names, scenario/run IDs, evidence or original file hashes, use:

```bash
python3 assessment-briefing/aggregate.py --source ./original-private-lab.json --output-dir ./NEW-PRIVATE-AGGREGATE
```

This prepares a scriptless printable `private-human-aggregate.html` and the corresponding `private-human-aggregate.json`, using only original **source-declared totals**: endpoint/finding counts, severity distribution, records with an evidence-reference list and records with an evidence-summary. Neither file carries original finding names, IDs, targets, run labels, scenario labels, evidence text or source hashes. All permission and validity flags are explicitly false, and actionable human questions are supplied without inferring fixes or execution. Success exit code is 2 (REVIEW_ONLY). **Aggregate counts can still reveal sensitive information**, so use only a separately approved private channel. Not a release, not a source authenticity signature, and not a public safe-to-share certification.

## NEW: completed human worksheet → PRIVATE follow-up return

The original `human-followup.csv` is now genuinely reusable. After a human fills the **four original human columns** (`human_stage`, `human_owner_group`, `human_next_action`, `human_blocker`) in a PRIVATE local spreadsheet, close the file and export it as UTF-8 CSV with the original seven headers and original row ordering. Human stage may be blank or `needs_review`, `discussing`, `blocked`, `documented`; the program never infers approval from any value.

```bash
python3 assessment-briefing/human_return.py \
  --source ./original-private-lab.json \
  --manifest ./NEW-PRIVATE-BRIEFING/manifest.json \
  --worksheet ./human-filled-followup.csv \
  --output-dir ./NEW-PRIVATE-HUMAN-RETURN
```

This strictly reopens the same independently obtained original lab file and verifies its **exact unsigned source-byte digest** against the original briefing manifest, original endpoint/finding totals, the complete seven-column worksheet header, EVERY original ordinal, EVERY original severity and its evidence-reference count before touching output. CSV size is limited to 1 MiB, human owner to 120 characters, each action/blocker to 600, and unknown status values or altered membership HOLD the whole import. There is no silent row matching or partial application. Both supplied original lab and worksheet are still untrusted local files; the unsigned manifest does not authenticate the producer or human identity.

Creates an entirely NEW 0700 private directory containing `private-human-return.html` (printable scriptless private per-finding human plan plus original unchanged evidence in optional detail panels) and `private-human-summary.json` (self-reported status counts and no human names/notes). Each file is 0600, and any previous outputs or original source remain unchanged. Human edits are labels/proposals only, not verified remediation, approval, source authenticity, real-time consent, accepted scope or authorization. Exit 2 is REVIEW_ONLY and exit 3 is HOLD.

## NEW: compare two source-bound HUMAN revisions (same original source)

No code or model infers that a review-status movement proves an improved exposure. Compare two separately saved editable human worksheets against the **exact same original original lab source and original briefing manifest**:

```bash
python3 assessment-briefing/human_revision.py \
  --source ./original-private-lab.json \
  --manifest ./NEW-PRIVATE-BRIEFING/manifest.json \
  --before-worksheet ./human-before.csv \
  --after-worksheet ./human-after.csv \
  --output-dir ./NEW-PRIVATE-HUMAN-REVISIONS
```

Both human CSVs are independently admitted in full using the same strict original-ordinal/severity/evidence-count contract; all changes are then explicitly compared by HUMAN stage, group, proposed action and blocker. The new private scriptless `private-human-revisions.html` shows only changed human fields with PRIVATE original finding titles; `human-revision-counts.json` contains only numeric change / HUMAN stage-transition totals and unsigned fingerprints (still PRIVATE). Ambiguous membership or unmatched source HOLD the entire operation, leaving all prior source and review files untouched. Original finding text, actual evidence, target state, client consent, reviewer identity or source authenticity are never modified or verified.

## One-menu private operations console

For people who prefer not to assemble five different long commands, the companion offers a complete **foreground local menu**:

```bash
python3 assessment-briefing/console.py
```

Choose the detailed original briefing, two-source drift, privacy-minimal aggregate, original HUMAN return or original HUMAN revision comparison; enter only explicit local existing input paths and one NEW output directory. The console displays exactly the private disclosure profile of the chosen workflow and requires an explicit `REVIEW ONLY` confirmation. Invalid options, cancelled input, CTRL-C or declined disclosure do not run a source operation. Original execution/scan/grant/production routes are never touched and no existing output is overwritten. It intentionally returns 2 for a prepared private review packet, and 3 for cancellation/HOLD.
