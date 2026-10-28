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

### Interactive previous-versus-current source history

Archive Studio and the private ZIP review room now optionally accept an earlier
owner-private archive as --previous. The interactive page shows historical
source-byte changes beside editable human follow-up stages; users can filter
to newly selected or retained byte sources without ever contacting a target.
Both manifest snapshots are independently strictly admitted locally. Previous
HOLD remains a HOLD for the comparison even if the current manifest is
REVIEW_ONLY. A missing source is never considered a fixed vulnerability.

    python3 assessment-archive/packet.py --manifest /private/NEWER.json --previous /private/OLDER.json --include-studio --output /private/NEW-local-review-room.zip

Historical Studio is not available in anonymous ZIPs; this boundary is enforced,
not silently downgraded. The existing standalone source comparison CLI still
works independently.

### Human follow-up planning agenda · console option 10

The project now also supports a human-reviewed agenda for many already-indexed
source artifacts with **explicit planning reference date**, sorted private
source slots and non-approving role-specific next conversation prompts.

    python3 assessment-archive/agenda.py --manifest /private/ARCHIVE.json --choices /private/EDITED-followup.json --as-of 2026-10-18 --format html --output /private/NEW-human-agenda.html

The original manifest and human follow-up form are cryptographically byte-bound;
a different source or corrupted stage/role/date is rejected. Three printable
or machine-readable formats are available (HTML, Markdown, JSON). Each preserves
the original source owner worklist with human proposed dates categorized as
PAST_PLANNED_DATE, PLANNED_FOR_REFERENCE_DAY, FUTURE_PLANNED_DATE, UNSCHEDULED.
The agenda sorts planned human attention by date category and static source
question. It does not infer risk, legal deadlines, overdue SLAs, fixed
vulnerabilities, authentic consent or a pass/fail security verdict.

--aggregate-only removes individual source slots and dates, replacing them
with anonymous counts by human stage, neutral role and planned-date category.
All output is exclusively new, 0600 and fsynced. Original QA/CI and
authorization owners are untouched.

### Source-bound human agenda in portable coordination ZIP

The private or aggregate-only coordination ZIP can now contain a printable
human agenda generated directly from its **same original source-bound human
form**. The operator explicitly chooses a planning reference date, never
an automatic client grant or deadline:

    python3 assessment-archive/packet.py --manifest /private/ARCHIVE.json --choices /private/FOLLOWUP.json --agenda-date 2026-10-18 --include-studio --output /private/NEW-coordination-room.zip

The local index.html launches human-agenda.html alongside the original
archive dashboard, optional human worklist and private Studio. If
--aggregate-only is specified, the agenda exposes only anonymous group
counts for human stage, role and date relation (not individual slots,
dates or source fingerprints). Source and planning date inputs are
validated before the ZIP is published as one new 0600 artifact.
--agenda-date without the matching --choices source is refused as HOLD.

### Locally inspect a transferred coordination ZIP · console option 11

Every newly generated private/aggregate coordination ZIP now includes
packet-integrity.json: a deterministic fixed-name ledger of member byte
lengths and SHA-256 fingerprints, excluding the ledger itself. A recipient
can inspect the already-created local ZIP **without extracting, executing,
opening a browser, contacting a sender, or touching any lab source**:

    python3 assessment-archive/packet_inspect.py /private/RECEIVED-coordination.zip --output /private/NEW-inspection.json

The inspector bounds the overall ZIP size, expanded member sizes, accepted
member names, archive Unix regular-file permissions and compression, rejects
duplicate/unknown/traversing members, checks declared SHA-256 for every
member and validates the private/aggregate receipt and false-authority flags.
For aggregate-only packets it also rejects an embedded private Studio or
private manifest fingerprint in structured metadata. The recipient's
inspection output contains only mode, counts, advertised human components
and byte-match status. Inspection runs entirely locally, does not extract
or execute any member, writes an optional NEW private 0600 receipt, and
always returns REVIEW_ONLY (2) or HOLD (3), never successful permission.

**This is byte consistency, not sender authentication or independently
verified source provenance.** A sender could deliberately supply malicious
files with matching self-declared hashes. Do not open untrusted HTML or
rely on a ZIP for target access before independent source-owner,
security/privacy and real human authorization gates. Original lab results,
targets, approval and raw evidence are absent from the handoff.
