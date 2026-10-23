# LightUp · Offline Assessment Agenda Portfolio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.** This is a human-planning product built entirely in a **new isolated `assessment-portfolio/` source area**. It never inspects targets, invokes a model, dispatches workers or asks for an assessment grant. Original sources, reviewers and all release gates remain separate and unchanged.

## Problem solved

The original [assessment archive agenda](../assessment-archive/README.md) supports a human follow-up worklist for one byte-bound archive. When an operator has several *already produced* original private agenda exports, this program makes one coherent offline view of suggested review dates, neutral roles, work-stage queues and unchanged source HOLD states.

The private report uses only source ordinal + original slot. It does not copy finding names, source paths, client names, evidence, targets or credentials. SHA-256 is retained only in the separately named **owner-private** sidecar inside the ZIP; a digest is not proof of authentic source ownership. Different agendas can refer to the same original source; therefore portfolio totals are **human-workload counts**, not deduplicated vulnerabilities.

## How to use

First create **real original** human agenda JSON exports using the unmodified original source owner:

```sh
python3 assessment-archive/agenda.py --manifest /private/source-a-manifest.json --choices /private/source-a-human.json --as-of 2026-10-18 --format json --output /private/original-a-agenda.json
python3 assessment-archive/agenda.py --manifest /private/source-b-manifest.json --choices /private/source-b-human.json --as-of 2026-10-18 --format json --output /private/original-b-agenda.json
```

Then build the complete **offline private portfolio room** (up to 12 agendas):

```sh
python3 assessment-portfolio/portfolio.py \
  --agenda /private/original-a-agenda.json \
  --agenda /private/original-b-agenda.json \
  --as-of 2026-10-18 \
  --output /private/NEW-portfolio-room.zip
```

Extract privately. Open `index.html` in your browser. The package includes:

- `index.html` — sortable-by-human-priority static full private queue.
- `interactive-capacity-studio.html` — complete private in-browser week/role-capacity editor, instant hypothetical slot recomputation and aggregate-only download.
- `original-human-review-studio.html` — standalone private browser editor of human-only review fields, with exact original source digest proposal handoff. Importing a proposal back into the unchanged original schema requires the explicit, strict CLI described in [REVIEW-RETURN.md](REVIEW-RETURN.md). See [STUDIO.md](STUDIO.md).
- `private-source-bindings.json` — source digests and human work rows, **owner-private, never anonymized**.
- `aggregate.html`, `aggregate.json`, `aggregate.csv` — human counts only (roles, planning dates, stages) with literally false authority flags.
- `START-HERE.txt` — handoff rules.

Optional standalone outputs, each to a separate **new** owner-private file:

```sh
python3 assessment-portfolio/portfolio.py --agenda /private/original-a-agenda.json --as-of 2026-10-18 --format private-html --output /private/NEW-board.html
python3 assessment-portfolio/portfolio.py --agenda /private/original-a-agenda.json --as-of 2026-10-18 --format aggregate-json --output /private/NEW-human-summary.json
```

All source inputs must be the original *private* JSON agenda schema, complete with source rows. Aggregate-only original inputs cannot masquerade as full source-bound records. Input is capped at 256 KiB per file, 1–12 files and 64 original source slots per agenda. Same reference date is required, to prevent mixing incompatible overdue/not-due buckets. Duplicate JSON keys, misleading role/stage/date counts, missing original members, changed source rows, incorrect labels, authority assertions, malformed dates, duplicate agenda bytes, symlinks and nonregular input types are rejected **before any output is written**. The exact original source reader does not follow symlinks. Source captures are *unsigned*; integrity is not independent authentication.

Output uses the original trusted private publisher: atomic completed 0600 file with a no-overwrite destination. The operator must choose a trusted private directory; the program never enumerates directories to locate source files.

**Exit codes:** 2 = created for human review only; 3 = a retained original HOLD or an input/output failure. There is no exit 0 indicating authorization or release. `--help` may exit 0 normally.

## Privacy and original safety gates

Even the anonymized counts may be sensitive in a very small portfolio; humans must confirm recipients separately. The ZIP contains original private source digests and human work IDs; do not distribute it as a public report. Empty/missing work from a new agenda never means a vulnerability was repaired. A proposed date is not a legal deadline, consent or SLA breach.

The original [lab comparator #1515](https://github.com/Zennay/Lightup/pull/1515), [integrated held workbench #1625](https://github.com/Zennay/Lightup/pull/1625), original lab/authorization services, original CI and concurrent active branch owners were **not modified**. Original exact-head hosted and permanently registered VPS CI, independent source owner/privacy/security approval, genuine separately authenticated client/operator consent with action-time revocation and explicit HUMAN GO are still mandatory before any main merge, production deployment or live target work. No QA/regression/testsuites are added or run.

## Independent human-capacity workflows

Use [CAPACITY.md](CAPACITY.md) for role-specific command-line hypothetical capacity planning, or [STUDIO.md](STUDIO.md) for interactive browser-first capacity management. Both use the exact original private agenda admission path and never execute a target or claim real approval. The main workspace ZIP now contains the complete ready-to-open interactive capacity Studio automatically.

## Original-schema roundtrip for human follow-up

The new [private human return workflow](REVIEW-RETURN.md) lets the operator edit only human stage, neutral next role, and proposed follow-up date in a local browser. The original immutable manifest, original human choices and original agenda must all still match before the new — never overwritten — original-schema choices document is published. This is a separate human planning return only; original assessment/source owners, lab/execution authority and release gates remain untouched.

## Confidential multi-source original choices handoff

For **2–12 independent original source archives** with their original manifests, original choices, original agendas and private browser proposals, the new [multi-source human return](MULTI-RETURN.md) builds a single atomically published private ZIP containing separate original-schema human choices for every source, private original-manifest fingerprints and a static human-only inventory. The entire batch HOLDs before publication on even one stale or conflicting source. No source files are overwritten and no human action is executed.

### Bulk editing, private review diff and resume

The bundled original human review Studio now supports selected-row bulk human-only changes, a live old/new private follow-up diff, and private proposal re-import after closing the browser. Every imported original field is matched against the immutable exact original source digest and prior human values before replacing the local in-memory draft. The original ‘receive’ CLI still requires the original manifest, choices and agenda to accept the human proposal and publish a **new** original-schema file; the browser alone grants nothing.

## Independent reviewer contributions on one original archive

Multiple operators can return 2–12 separately exported PRIVATE human proposals on one **unchanged original archive** using the new [disjoint human proposal merge](MERGE-REVIEW.md). All original source digests and old human slots must still match. If two proposals touch the same original slot, the entire batch HOLDs before any output is written: there is no silently chosen winner. A single owner-private atomic ZIP contains a newly merged ORIGINAL-schema human choices JSON, scriptless review and private source manifest, not a grant or assessment result.

## Save and restore private capacity assumptions

In the standalone private capacity Studio, human planners can download a PRIVATE source-hash-bound capacity plan and later restore the original neutral role/week settings only against exactly unchanged original agenda byte sources. The new [private capacity replay CLI](SAVED-CAPACITY.md) re-renders the hypothetical human work queue from those exact original agendas and the saved source-bound plan; no actual work is scheduled, assigned, executed or approved.

## Recommended one-command original-source entry

Operators who already possess original archive manifests and original source-bound human choices can now skip all manually exported intermediate agendas. The new [one-command original-source builder](ONE-COMMAND.md) accepts 1–12 ORIGINAL manifest+choices pairs and publishes a complete private, portable offline ZIP with original private agenda JSONs, all existing portfolio/Capacity/Review Studios, aggregate-only exports and source-bound human return instructions. No original scanner, authority, CI, existing source branch or tests are touched.

### Original workspace ZIP → human review return

Use [workspace_return.py](WORKSPACE-RETURN.md) to submit 1–12 offline review-Studio proposals against the same untouched original manifests and human choices. Complete source/ZIP binding is checked before publishing a single new private original-schema choices ZIP; no original inputs are changed and no authority is implied.

### Continue complete human review cycles

Use [review_cycle.py](REVIEW-CYCLE.md) to take a private one-command workbench, the unchanged original manifests and prior choices, and human review proposals, then atomically create both a **new private original-schema choices set** and a **new ready-to-open offline portfolio workbench** for an explicit planning date. Every source must rebind to its original identity; no original is edited.

The review-cycle ZIP also includes a [private human revision difference board](REVIEW-CYCLE.md) and separate counts-only stage-transition exports; stage/role/date edits are human notes only, not verified assessment changes.

### One-click all-agenda human return

The private Review Studio can now [export all original agenda human proposals as ONE source-bound JSON bundle](ALL-PROPOSALS.md); both `workspace_return.py` and `review_cycle.py` accept `--proposal-bundle` for a complete all-or-none private return. Individual proposal exports remain supported.

### One-page offline workspace navigation

Each newly generated portfolio (and every subsequent private review cycle) includes **[workspace-home.html](NAVIGATION.md)**, a scriptless local start page linking to the current human queue, cross-agenda Review Studio, hypothetical capacity studio and aggregate handoff, with the exact command-line next-cycle flow. Older original-source workspaces without this optional page remain readable by the original source-bound return command.

### Cross-agenda human review

The original private browser Review Studio now has a [single portfolio-wide human attention desk](CROSS-AGENDA.md), letting an operator filter all original agenda rows by stage, neutral role and planned-date status, bulk-edit human notes across different sources with explicit acknowledgement, and export the complete original-bound PRIVATE human proposal bundle. Original evidence and authority remain unchanged.

### Original offline package continuity

Every newly built original human workspace and revised next-cycle workspace includes a [private per-file byte correlation document](CONTENT-INTEGRITY.md). Original-source return checks all recorded HTML, report and bindings member bytes before accepting human proposals. This unsigned in-ZIP SHA map catches changed or missing bundle components; it does **not** prove genuine provenance or prevent an attacker from replacing both ZIP and map. Older private original ZIPs remain readable under their legacy original-source gates.

### Resume all human review proposals in one action

The original private Review Studio now [restores a previously exported complete all-agenda proposal JSON bundle](RESTORE-ALL.md) atomically in the browser: every source SHA, original prior human field, date, row and original source count must match before it replaces any in-memory draft. It uses the same strict per-source decoder for single source restores and remains non-authorizing.

### Explicitly continue original hypothetical review capacity

The [next private human review cycle](CAPACITY-CONTINUATION.md) can optionally rebind a previous strict original-source human Capacity Studio plan to the **NEW** original agenda hashes/date, only when the human independently supplies `--previous-private-capacity-plan` **and** `--reconfirm-human-capacity`. Its new private original-schema plan, role schedule and aggregates are included in the same new review-cycle ZIP, never applied to any real worker or task.

### Consecutive original human review history

Use [revision_history.py](REVISION-HISTORY.md) for a complete owner-private source-bound timeline of 2–12 consecutive previously exported original human review-cycle receipts. It refuses breaks in the original manifest/choices/agenda SHA sequence and unchanged original HOLD, and exports a scriptless visual local timeline plus counts-only summaries. Unsigned human changes are not proof of actual vulnerability or consent state.

The human review history also accepts **complete** prior review-cycle ZIP packages using [repeated `--cycle-zip`](REVISION-HISTORY.md). It checks original nested next-workspace/choices/agenda and optional human capacity bindings, avoiding any manual intermediate JSON extraction. This is still private unsigned human planning provenance, not real permission.

### Full-portfolio independent human collaboration

Use [portfolio_merge.py](PORTFOLIO-COLLABORATION.md) to combine 2–12 **complete** independently exported all-agenda original human proposal bundles against the exact same original 1–12 source manifests/choices/workspace. It rejects any same original agenda/slot overlap and exports one private merged bundle in the **existing** original human proposal schema for a later deliberate `workspace_return.py` or `review_cycle.py` handoff. No automatic downstream application, source changes or grants.

### One-command multi-human collaboration into NEXT review workspace

Use [collaboration_cycle.py](COLLABORATION-CYCLE.md) to merge 2–12 disjoint all-agenda human proposals and directly produce a new complete original-source-bound private human review cycle ZIP **in one operator command**, without extracting an intermediate proposal to disk. The original workspace, manifest/choices, reviewer bundles and HOLD remain immutable; real assessment and authorization are untouched. Optional hypothetical role capacity carries forward only after explicit independent human reconfirmation.

### Human mediation for overlapping original review proposals

When [multi-reviewer original human portfolio merge](PORTFOLIO-COLLABORATION.md) rejects overlapping original agenda/slot edits, generate a [standalone private original-source mediation Studio](PRIVATE-MEDIATION.md) via `portfolio_mediation.py` with the same original workspace/manifest/choices plus all reviewed source-bound bundles. Every original conflict requires an **explicit human choice** between contributor drafts or retaining the original human stage/role/date. The owner-private offline HTML only exports a new complete `--proposal-bundle` after every contested slot and independent private human-only acknowledgement; it does not silently merge, verify security findings, grant consent, or alter originals.

### Complete source-bound human conflict resolution into NEXT review cycle

Use [mediation_return.py](MEDIATION-RETURN.md) with the original offline workspace, original manifest/choices, every independently exported human reviewer bundle, a separately exported human-resolved original all-agenda private proposal and the explicit next planning date. It permits only exact original human prior values or originally proposed candidate human values at each source slot, then reuses the strict full original human return and next review-cycle gates to produce **one new private next-cycle ZIP** without any intermediate file or target action. An unsigned browser decision is never client permission.

### Original offline collaboration navigation

New complete original-source private assessment workspaces include [collaboration-guide.html](COLLABORATION-NAVIGATION.md) linked directly from `workspace-home.html`. It gives operators the full source-bound independent human contribution, strict conflict-free merge, explicit mediation and next-cycle return workflows without needing to find repository docs. The new guide is covered by the private local content byte-consistency map, and older original workspaces remain readable under their existing strict original-source gates.

## Strict JSON admission for private HUMAN restores

The standalone original-HUMAN review editor now admits single-agenda proposals
(256 KiB maximum) and complete all-agenda bundles (4 MiB maximum) through the
shared `strict-json.js` parser. The hypothetical capacity Studio uses the same
parser for source-bound capacity-plan restore (64 KiB maximum). All three paths
reject duplicate decoded object keys, including escaped spellings that would
otherwise collapse to one key under the browser's normal last-key-wins parser,
plus invalid JSON whitespace/tokens and non-finite numeric values. Their
existing exact-schema, source-digest, row-order, false-authority and atomic
in-memory validation remains in place.

The parser is embedded into each CSP-hashed standalone by the existing builders;
it is not fetched at runtime. Generated handoffs remain local, private and
non-authorizing. No original agenda, grant, scanner, consent or production
source-owner path is modified.

### Reopen the complete ORIGINAL private workspace without modifying it

[One-command original source workspace](ONE-COMMAND.md) accepts `--reopen-workspace PRIVATE.zip` instead of `--output`: with all original manifest/choices pairs and the same explicit reference date, it regenerates the entire original-source offline workspace and compares exact bytes to the owner-private ZIP, with no extraction or publication. A mismatch or changed source fails closed. A matching unsigned byte comparison does not prove consent, authorship, findings, or security readiness. Exit 2 remains REVIEW_ONLY; HOLD remains 3.

### Private recipient: inspect ZIP without source originals

[`inspect_original_workspace.py`](inspect_original_workspace.py) checks an existing owner-private original HUMAN workspace ZIP read-only against its own strict layout, original native agenda schemas, aggregate counts, source-binding ordinals and unsigned SHA-256 consistency inventory. It reports no private original source identifiers or dates. With no original manifest/choices it **cannot** prove source authentication, identity, finding validity, client/operator consent or authority. For full exact-byte reconstruction from held originals, use [`one_command.py --reopen-workspace`](ONE-COMMAND.md).
