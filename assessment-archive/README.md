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

### One interactive operator console

For the entire private intake-to-human-follow-up workflow, there is now one local terminal entrypoint:

    python3 assessment-archive/console.py

The menu exposes seven complete actions: capture, source integrity recheck, printable private/anonymized inventory, aggregate sharing, before/after source-delta, editable human planning form generation and source-bound worklist publication. The operator explicitly selects each input file, each output filename, and public versus private view. There is no directory scan, network, shell, model, target interaction, browser persistence, automatic source escalation, or non-0600 output. Invalid inputs yield a generic HOLD and return to the safe menu rather than exposing source paths. The console never offers an authorization, dispatch or GO action.

Use --help for noninteractive usage hints. The original individual commands remain usable independently, with the same source and security requirements.

### Portable, private coordination packet

For an all-in-one owner-private, existing-source-only handoff, package the archive inventory and optional matching human follow-up:

    python3 assessment-archive/packet.py --manifest /private/ARCHIVE.json --choices /private/EDITED-followup.json --output /private/NEW-coordination.zip

Or select --aggregate-only for a packet that does NOT contain source hashes, per-slot stages, human roles, dates, paths, finding text or target/client identifiers. Both packages contain a static HTML archive view, metadata JSON, an explicit no-authority receipt, and optionally an HTML human worklist. Original evidence/record files are NOT included and cannot be reconstructed from the packet.

Packet creation reuses one original private manifest byte snapshot and the exact original follow-up binding; a changed or mixed original source is a HOLD. ZIP members have deterministic local names and timestamps, source-neutral content and restrictive Unix metadata. The new ZIP is published atomically as a new 0600 private local file. Neither format certifies authenticity, data integrity beyond bytes, human consent, permitted active work, remediation or release. The console also offers this as option 8.

### Interactive browser-first Archive Studio

The console now offers choice 9: generate a fully self-contained, source-bound private HTML workbench for your original archive. The same workflow is available directly:

    python3 assessment-archive/archive.py studio --manifest /private/ARCHIVE.json --output /private/NEW-private-studio.html

Open NEW-private-studio.html locally to explore source slots, filter and search, select human follow-up stages/neutral roles/dates, import a previously source-matched draft, export a private JSON draft, export anonymous counts and print. No external resources or browser persistence. This is a **private** HTML containing the original archive source-byte hashes; do not publicly share it. The original strict followup.py render must validate the browser-downloaded draft before any archive handoff. See STUDIO.md.

### One-click private coordination ZIP with integrated Archive Studio

Use the existing packet CLI for a navigable **local portal**, archived source overview,
optional human worklist and fully interactive private Studio, all packaged from
exactly the same validated original manifest byte snapshot:

    python3 assessment-archive/packet.py --manifest /private/ARCHIVE.json --choices /private/EDITED-followup.json --include-studio --output /private/NEW-private-review-room.zip

The packet now always includes index.html, a responsive local launcher that links
to the original static archive inventory and optional worklist. Owner-private
--include-studio also adds source-bound interactive archive-studio.html where
the human can edit stages and export a new review draft. The ZIP contains no
original lab cases, targets, evidence or credentials. Local browser downloads
still require strict original Python revalidation.

**Privacy constraint:** --include-studio is rejected when --aggregate-only is
selected: the interactive page contains original private file byte fingerprints
and manifest SHA-256, so bundling it in an anonymous export would leak data.
Aggregate-only ZIPs still get the static script-free index, category counts
and (if supplied) anonymous human worklist; no Studio or hashes. All ZIP members
have fixed non-traversing paths and private metadata, and the outer ZIP is a new
exclusive fsynced 0600 output. Review before distributing any aggregate metadata.
