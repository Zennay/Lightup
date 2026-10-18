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
