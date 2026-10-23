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

## Opt-in offline JSON CLI (non-authorizing)

Use `python scripts/assessment_runtime_compare_cli_1513.py before.json after.json` with `PYTHONPATH=src`. Each file must be a JSON object with exactly `record` (a complete `EvaluationRecord.to_dict()` payload) and `context` (the eight fields of a lab `RunContext`, where `mode` is its enum string, `approved_risk` its integer, and `created_at` UTC ISO-8601). Both files must be at most 65,536 bytes. **No target is opened or contacted**; only those two local files are read. Duplicate JSON keys, NaN/Infinity, inconsistent derived FPR, malformed/mismatched lab provenance and oversized files return generic non-echo HOLD. Exit `2` means REVIEW_ONLY, `3` HOLD; **never exit 0** and neither status is consent, authenticated provenance, or production GO. Never place confidential target data in benchmark JSON; CLI does not echo invalid input.

## Atomic cohort JSON CLI

The opt-in `python scripts/assessment_runtime_compare_cohort_cli_1513.py baseline-cohort.json candidate-cohort.json` reads two **explicit local** JSON arrays, each containing 1–64 same-schema single-case `{"record":...,"context":...}` envelopes. Max 262,144 bytes per file. Every item must pass the same exact lab-record/context checks as the single-case CLI. Both scenario sets must match exactly. One regressed scenario => global `HOLD`; incomplete, duplicate or malformed files => generic `HOLD` with **no partial comparisons or input echo**. Valid non-degraded results => `REVIEW_ONLY`. Exit codes strictly 3 or 2, **never 0**. Results carry all four immutable false security-authority flags; this is an offline diagnostic only and cannot substitute real consent, provenance or release evidence.

## Optional exact lab scenario and ground-truth fence

Use `compare_ground_truthed_lab_evaluations(baseline_scenario, candidate_scenario, baseline_record, candidate_record, baseline_context, candidate_context)` from `lightup.ai.assessment_runtime_scenario_1513` for trustworthy **like-for-like** interpretations. This purely in-memory wrapper requires canonical exact `LabScenario` types, the **identical** name/description, normalized loopback/private targets and original endpoints, and complete equal expected-finding identifier/title/capability/severity lists. An unscored scenario (`expected_findings=None`), duplicate planted identifier, target drift, unexpected ground truth change, malformed scenario, or mismatched tenant -> generic `HOLD` **without input echo**. `expected_findings=()` explicitly scores a zero-finding lab and is permitted.

This is a caller-supplied scenario identity consistency diagnostic, **not** a cryptographic attestation that fixture bytes or underlying lab environment are unchanged. Even an exact match cannot grant authorization, consent, dispatch or release.

## Post-construction lab asset integrity (opt-in)

The scored-scenario adapter now independently rechecks every exact target/endpoint
pair *after* `LabScenario` construction: it requires the original normalized
loopback/private-lab host and a matching original endpoint, using only local
URL parsing and `ipaddress`, without DNS, sockets, active tools or scans.
Frozen dataclasses can be forcibly rebound by in-process code; even if two
forged snapshots match each other, public, multicast, unspecified and
mismatched lab endpoints produce generic HOLD. This is a defensive
unauthenticated data-consistency check, **not** the production scope gate.

## Atomic scored-scenario cohorts (opt-in)

`compare_ground_truthed_lab_cohorts(baselines, candidates)` from
`lightup.ai.assessment_runtime_ground_truth_cohort_1513` compares 1–64
`(LabScenario, EvaluationRecord, RunContext)` tuples on each side. Both
complete scenario-ID sets and their explicit full ground truth and lab assets
must match. Outputs are ordered by scenario ID; one adverse metric => HOLD,
while an invalid/missing/duplicated, changed or forged scenario => *generic*
HOLD without any partial comparisons or sensitive input echo. The wrapper
performs no I/O and never produces authority: all four consent, authorization,
dispatch and release flags are false even for REVIEW_ONLY. Source provenance,
consent, registered permanent VPS CI and human GO remain entirely unproven.

## Exact source-head hosted regression gate

The dedicated assessment-runtime hosted Python matrix checks out the explicit
PR-head commit instead of GitHub's temporary pull-request merge ref. The
assertion compares `git rev-parse HEAD` with the immutable event head SHA
before any offline test runs. This test verifies *only* the isolated local
assessment-runtime suite, not full project hosted or registered VPS release
gates; the permanent operator-owned VPS job is tracked independently.

## Explicit scored-cohort JSON CLI

Run `PYTHONPATH=src python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py old.json new.json`
with two explicitly selected, at-most-262144-byte local JSON arrays (1..64).
Each item has exactly `scenario`, `record`, `context`. `record` and `context`
use the existing complete lab evaluation schema; `scenario` has exactly
`scenario_id`, `name`, `description`, `targets` (original host strings),
`endpoints` (same original strings), and `expected_findings` (complete explicit
list of `identifier`, `title`, `capability_id`, `severity` objects).
No live targets, network, worker, grant or persistence are used. Invalid,
public/nonlab, forged, duplicate, inconsistent or oversized packets cause
**generic HOLD** without partial output or input echo. A valid nonregressed
packet is only an unauthenticated `REVIEW_ONLY` and exits **2**; regression or
invalid input exits **3**; exit zero is impossible. Four authority fields are
always false. Do not use with genuine client secrets or as release evidence.

## Baseline replay is not an independent candidate

The offline evaluator now rejects the *same* record ID or run ID on both
sides, even when metrics are perfectly valid. Reusing the original baseline
as the proposed candidate silently manufactures a non-regression result;
now it returns generic HOLD without per-metric output. This exact identity
check is a narrow diagnostic integrity check and is NOT cryptographic run
provenance, authorization, client consent, or release approval. The JSON
CLI, scored-scenario comparisons and cohorts inherit the same rejection.

## Offline CLI input-file admission

The three JSON command-line entry points share the same bounded file reader:
the single-case comparator, the ordinary cohort comparator, and the scored
ground-truth cohort comparator. The reader is deliberately fail-closed on
Linux systems where the required descriptor flags or `/proc/self/fd` are
unavailable.

- Every user-supplied directory component is opened relative to a pinned
  directory descriptor with no-follow semantics; ambiguous `.` and `..`
  components are rejected instead of normalized.
- The final entry must be a regular file. An `O_PATH` descriptor pins the
  inspected inode before a separate read descriptor is opened, preventing a
  raced FIFO or device from becoming the read source. `O_NONBLOCK` prevents
  FIFO hangs as an additional defensive layer.
- The read remains bounded by each CLI's existing byte limit. Descriptor
  identity, size, mode, modification time, and change time are compared before
  and after reading, along with the final no-follow directory entry. A replaced,
  symlinked, special, oversized, empty, or concurrently changed input is
  rejected and follows the existing generic `HOLD` output.
- This is local input hardening only. It does not authenticate caller-provided
  lab provenance, grant consent, contact targets, or change any execution,
  authorization, dispatch, or release gate.

## Optional human-readable cohort summary

The cohort CLI keeps compact JSON as its default output so existing structured handoffs, including Assessment Trends, remain unchanged. For a terminal-friendly view, add `--format text`:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format text baseline-cohort.json candidate-cohort.json
```

The text view lists each result using a local anonymous ordinal (`Scenario 01`, etc.), then shows the source-reported metric baseline, candidate, delta and regression flag. It reports cohort-level status and counts without printing the original scenario IDs or input paths. Invalid or inconsistent input remains a generic `HOLD` with no partial scenario detail. The exit contract is unchanged: `2` means `REVIEW_ONLY`, `3` means `HOLD`; zero is never a success signal. This remains a local diagnostic, not authenticated provenance, remediation evidence, consent, authorization or release approval.

