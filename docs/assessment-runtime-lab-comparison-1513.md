# Assessment runtime: offline benchmark comparison (#1513)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

Opt-in, read-only comparison of two *already-recorded* `EvaluationRecord` objects with their `RunContext` snapshots. The comparator is not wired into product dispatch. No filesystem, network, scans, provider calls, handler calls, state writes, grants, report verdicts, or execution authority.

## Why this exists

Different planner/model revisions can improve overall findings while silently worsening specific benchmark categories. `compare_lab_evaluations` returns stable per-metric old/new/delta entries in declared order, plus the exact adverse metric names. It blocks comparison of different scenario IDs, non-lab context, mismatched run/engagement provenance, malformed numeric data (including known pending `EvaluationMetrics.validate` issue #834), subclass/type confusion and non-finite numbers.

A degraded primary metric returns **HOLD**; a syntactically consistent comparison without primary regressions returns **REVIEW_ONLY**. Performance/runtime and monetary cost deltas are informational, not gating. `REVIEW_ONLY` is *never* a pass to release or execute. Both records and their contexts are supplied by the caller; matching them does **not** establish authentic provenance, client/operator consent, revocation-at-use, independent security review, or actual ground truth.

Example (offline, in-process):

```python
from lightup.ai.assessment_runtime_diff_1513 import compare_lab_evaluations

# baseline_record/candidate_record are already persisted evaluation records;
# baseline_context/candidate_context are corresponding lab-only run snapshots.
diagnostic = compare_lab_evaluations(
    baseline_record, candidate_record, baseline_context, candidate_context
)
print(diagnostic.status, diagnostic.regressions)
# This status never grants scan, authorization, dispatch, or release permission.
```

## Ownership and validation

Issue [#1513](https://github.com/Zennay/Lightup/issues/1513). Dedicated assessment-runtime branch; exclusively new source/test/docs/workflow paths. Do not modify adjacent scope-authorization owners, evaluation-metric source owner [#834](https://github.com/Zennay/Lightup/issues/834) / [#835](https://github.com/Zennay/Lightup/pull/835), finding review [#846](https://github.com/Zennay/Lightup/pull/846) / [#847](https://github.com/Zennay/Lightup/issues/847), other workers, or real executor.

This isolated test job is diagnostic only. Full-project hosted tests, independent security/privacy, permanent named VPS test, separately verified client+operator approval and live revocation, and explicit human GO remain required. **Never merge/deploy based on this comparator.**

## Multi-scenario cohort extension

`compare_lab_cohorts(baselines, candidates)` compares 1–64 independently labelled lab scenarios in one atomic, sorted diagnostic. Inputs are tuples of `(EvaluationRecord, RunContext)` pairs, one pair per unique scenario. Both sets must have **exactly the same scenario IDs**; missing, extra, duplicate, malformed, non-lab, or oversized inputs return generic HOLD with no partial detail. Any single adverse scenario returns HOLD even if other scenarios improved. Results have four false authority flags, and no target access or producer changes are introduced.
