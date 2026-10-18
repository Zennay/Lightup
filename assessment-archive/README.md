# LightUp · Offline Lab Artifact Archive

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Product source for an independent, offline human-review inventory. It does **not** release the assessment runner, grant permission, inspect assets, perform vulnerability analysis, authorize a client/operator, approve a lab baseline or establish authentic provenance.

This standalone tool is intentionally separate from the currently owned original source/composition branches. It can be integrated into the existing assessment workspace after source-owner and security/privacy review without changing the original comparator, Lab Scenario Studio, authorization policy or evidence review.

## Why this exists

The original comparator and Review Desk serve an individual baseline/candidate comparison or completed review handoff. A reviewer dealing with **2–64 distinct already-created artifacts from several sessions** needs an **offline library index** and a byte-integrity check without manually transferring source identifiers, raw findings or private paths into a shared report. This utility adds that multi-artifact overview; it does **not** duplicate or replace original comparison, human triage or the lab runner.

## Operator workflow

Requires only Python 3.11+ stdlib and the explicitly selected **local source files**. No PYTHONPATH, internet, credential or optional package is required. The tool never enumerates folders.

```bash
python3 assessment-archive/archive.py capture \
  /private/completed-lab-case-A.json \
  /private/completed-lab-case-B.json \
  /private/comparison-result.json \
  --output /private/NEW-archive-index.json
```

Supported source *claims*: pre-existing JSON `{"record": {...}, "context": {...}}` completed lab case(s), original offline comparison JSON (`status` + `comparisons` or `changes`), human-authored Lab Scenario Studio catalogs, other explicitly `lightup.*` draft documents, and **opaque** local ZIPs (member metadata only; no unzip or trust). Importing a source **does not** authenticate its creator, intended customer, grant, target, claims, metrics or security findings. An active source, preview-only artifact, unrelated JSON or ambiguous/malformed source is not silently relabeled as completed.

The private index contains only ordinal source slots, byte lengths, file-type claims, limited claimed item counts, local SHA-256 byte fingerprints, and REVIEW_ONLY/HOLD. It does not persist source paths, raw target labels, customer IDs, names, exact scenario IDs, finding text or evidence content. Still treat it as **PRIVATE**, because hashes, sizes and counts can sometimes reveal sensitive details.

### Recheck the identical selected sources

```bash
python3 assessment-archive/archive.py verify \
  --manifest /private/NEW-archive-index.json \
  /private/completed-lab-case-A.json \
  /private/completed-lab-case-B.json \
  /private/comparison-result.json
```

All original files must be provided again **in the same order**; original content, byte lengths, SHA-256, JSON shape and claimed review status must match. Does not re-run any evaluator or test. All source checks use no-follow, bounded, regular-file descriptors, never symlinks/devices/FIFOs.

### Private printable workspace

```bash
python3 assessment-archive/archive.py view \
  --manifest /private/NEW-archive-index.json \
  --output /private/NEW-owner-private-dashboard.html
```

Open that HTML **locally**. It is self-contained, keyboard-readable and print-friendly; there is no JavaScript, remote dependency, storage, form, telemetry, network access or automatic file import. Hashes are shown only on this private view.

### Aggregate-only human handoff

```bash
python3 assessment-archive/archive.py share \
  --manifest /private/NEW-archive-index.json \
  --output /private/NEW-aggregate-only.json

python3 assessment-archive/archive.py view \
  --manifest /private/NEW-archive-index.json \
  --aggregate-only \
  --output /private/NEW-aggregate-only.html
```

The anonymous version includes category totals, total selected files and claimed HOLD count. It deliberately excludes hashes, local paths, original source slots, dates, target data, findings, personal information or labels. Some metadata counts may still be sensitive, so review before sharing.

**Exit semantics:** `2` means source documents are available for **human review only**. `3` means **HOLD**, including rejected input. Neither command returns `0` to convey successful clearance. CLI `--help` may exit normally. Errors are deliberately generic so that potentially sensitive original paths/source details are not repeated.

**Atomic publication:** All output files are new, exclusive (never overwritten), mode `0600`, streamed into an fsynced temporary regular file and published by no-replace hardlink. A write conflict or missing destination rejects the operation. Use a private output directory with trusted local permissions.

## Original integration boundaries

- [Active original composite assessment runtime PR #1621](https://github.com/Zennay/Lightup/pull/1621): combines the original comparator, Review Desk, Studio, Lineage Desk, Candidate Matrix.
- [Held original lab-assess runtime PR #1610](https://github.com/Zennay/Lightup/pull/1610): controlled endpoint selection and private lab assessment, not invoked here.
- [Original comparator PR #1515](https://github.com/Zennay/Lightup/pull/1515): source-of-truth metrics, not recalculated here.
- [Original private review handoff PR #1617](https://github.com/Zennay/Lightup/pull/1617): same-case review ZIP, not modified here.

**Release is still prohibited.** Full original hosted and registered permanent VPS exact-head CI, original source-owner integration, independent privacy/security review, authentic separate customer/operator approvals, action-time revocation where required and explicit HUMAN GO remain prerequisites. No QA suites, existing application tests, scanners, model calls, target endpoints, SSH bypass or production deployment are required or added by this local archival extension.

### Compare successive owner-private archive captures

Two already-created private manifests can be compared without reloading any original target/evidence files:

    python3 assessment-archive/archive.py diff --previous /private/OLDER-archive-index.json --current /private/NEWER-archive-index.json --output /private/NEW-archive-change.json

This contains private SHA-256 fingerprints of newly added and no-longer-present source bytes, plus source-class deltas and unchanged counts. A missing source is NOT a repaired vulnerability, and a changed file is not a verified assessment. Use --aggregate-only for anonymous counts and category changes without fingerprints. No dates, labels, source paths or customer-identifying details are transferred. A HOLD in either source remains HOLD in the change report, and all permission/release flags remain false.

### Visual source-delta dashboard

Choose HTML for an actual standalone source delta workspace: three added/absent/unchanged cards, source-class change table and (owner-private mode only) original SHA-256 byte fingerprints. The aggregate version contains no hashes.

    python3 assessment-archive/archive.py diff --previous /private/OLDER.json --current /private/NEWER.json --format html --aggregate-only --output /private/NEW-change-dashboard.html

This static offline report does not infer that a missing source is a repaired vulnerability. Its CSP forbids external resources, JavaScript, network, forms and browser persistence. Output is an exclusive 0600 HTML file.
