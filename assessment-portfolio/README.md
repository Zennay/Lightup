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
