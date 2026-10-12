# W59 — isolated allocation/RSS observations for optional downstream HTML reviewer (#1221)

**Status: LightUp Incubate M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.** This is a **test-only, opt-in, wholly synthetic** addition. The uninstalled W51 HTML reviewer is not the real Markdown engine, HTML5 browser or a production authorization/privacy/security control.

## Provenance and collision avoidance

- Parent: immutable W58 [DRAFT #1235](https://github.com/Zennay/Lightup/pull/1235) exact `5960cf9d7ce1d50f294b4e428ecd392b56a11e28`.
- Branch: `test/evidence-w59-html-reviewer-allocations-20261012`.
- Exactly new `tests/test_markdown_html_reviewer_allocations_w59.py` and this separate note. No production source, existing reviewer helper, original #894/#100/#732 files, default web/auth/CLI/report, `main`, other worker branches, real clients/assets or target interaction.

## Independent memory-observation contract

Six separate fresh Python **Linux** subprocesses execute W51's optional conservative synthetic HTML gate against deliberately generated fixtures: ~1.4 MiB of escaped entities; 25,000 small nested-list fragments; large input with a late invalid `<br / >`; greater-than-4-MiB UTF-8 source ceiling; normal Unicode/emoji; and a surrogate UTF-8 refusal. Each child hashes the unmodified source with SHA-256 before and after, asserts exact deterministic acceptance/refusal (`ValueError("invalid downstream finding html integrity")`), and prints only the `W59_SYNTHETIC_METRIC` lab record (numeric `tracemalloc` peak and Linux `ru_maxrss` high-water before/after, never source text).

The 128 MiB Python-tracked peak ceiling is an intentionally generous **test-laboratory regression tripwire**, not a memory quota, process RSS bound, allocation-free claim, production SLO or evidence that a browser DOM cannot grow. `ru_maxrss` is a process-lifetime high-water mark and its before/after difference **may be zero even when allocations occurred**; high-water observations are collected but no zero-RSS-allocation claim is made. Six cases run in independent fresh processes so one case's high-water does not contaminate another.

## Hosted acceptance

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_markdown_html_reviewer_allocations_w59
```

Use complete hosted Python 3.11/3.14 full unit + genuine producer integration logs for the **exact final W59 head**, then separately require the **registered permanent VPS self-hosted CI**; a queued run is not proof. Record numeric samples per interpreter only after reading raw logs; do not copy or infer metrics from different commits.

Original owners, independent security/privacy/tenant authorization, selected real pinned Markdown→HTML engine, downstream browser/DOM/CSP, safe latest-main integration and explicit release approval are **independent gates**. No real client evidence, scans, grants, executed remediation, retest, target communication, merge or deployment.
