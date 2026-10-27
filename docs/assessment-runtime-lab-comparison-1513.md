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

## Opt-in single-case JSON/text CLI (non-authorizing)

Use `python scripts/assessment_runtime_compare_cli_1513.py before.json after.json` with `PYTHONPATH=src`. Each file must be a JSON object with exactly `record` (a complete `EvaluationRecord.to_dict()` payload) and `context` (the eight fields of a lab `RunContext`, where `mode` is its enum string, `approved_risk` its integer, and `created_at` UTC ISO-8601). Both files must be at most 65,536 bytes. **No target is opened or contacted**; only those two local files are read. Duplicate JSON keys, NaN/Infinity, inconsistent derived FPR, malformed/mismatched lab provenance and oversized files return generic non-echo HOLD. Exit `2` means REVIEW_ONLY, `3` HOLD; **never exit 0** and neither status is consent, authenticated provenance, or production GO. Never place confidential target data in benchmark JSON; CLI does not echo invalid input.

### Optional privacy-minimal terminal output

JSON remains the default for existing structured handoffs. Add `--format text` for a readable terminal summary:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cli_1513.py \
  --format text before.json after.json
```

The text output lists each metric's baseline, candidate, delta and source-reported flag without echoing scenario identifiers or input paths. Invalid or inconsistent input prints only a generic HOLD summary, with no partial metric details. The exit contract remains `2` for REVIEW_ONLY and `3` for HOLD; zero is never a success signal. All four authority flags remain false, and this output does not establish source authenticity, remediation, consent, authorization or release approval.

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

## Explicit scored-cohort JSON/text CLI

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

### Optional privacy-minimal terminal output

JSON remains the default. For a readable scored-cohort report, use:

```sh
PYTHONPATH=src python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py \
  --format text old.json new.json
```

The text summary reports the cohort status and anonymous scenario ordinals, then lists each metric's baseline, candidate, delta and source-reported flag. It deliberately omits scenario IDs, target addresses, planted finding identities and input paths. Invalid or inconsistent input produces a generic HOLD with no partial case details. Exit `2` means REVIEW_ONLY, `3` means HOLD; zero is never a success signal. The output is not authenticated ground truth, consent, authorization or release evidence.

## Spreadsheet-ready offline CSV handoff

The same three local CLIs also accept `--format csv`. This generates a long-form CSV with one row per admitted metric and anonymous scenario ordinal, suitable for spreadsheet filters or pivot tables. As with HTML output, the operator explicitly chooses any output filename using shell redirection:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cli_1513.py \
  --format csv before.json after.json > single-lab-review.csv

PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format csv baseline-cohort.json candidate-cohort.json > cohort-lab-review.csv

PYTHONPATH=src python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py \
  --format csv old.json new.json > scored-lab-review.csv
```

The CSV has the columns `report_type`, `source_status`, `input_admitted`, `scenario_ordinal`, `metric`, `baseline`, `candidate`, `delta`, `source_regression_flag`, `source_unknown_coverage`, `authorized`, `consent_verified`, `dispatch_allowed`, `release_allowed`, `review_only`, and `source_provenance_authenticated`. Every authority/provenance field is the literal string `false`; `review_only` is `true`. Only original comparator-admitted numeric values and fixed metric-name tokens enter the cells; negative deltas remain valid negative numeric cells. No free text, input filenames, source IDs, target addresses, raw evidence, client/operator identifiers or notes are exported.

A rejected packet generates only the column header and one generic `HOLD` row with `input_admitted=false` and **no numeric or source-detail cells**. A valid comparison can also be `HOLD` when source adverse flags are present; then `input_admitted=true` and the metric rows are available for human inspection. The `source_unknown_coverage` field indicates a source-reported candidate unknown-coverage value above zero; it is **not** converted into a new regression label.

All three formats (`json`, `text`, `html`, `csv`) retain exit code **2 REVIEW_ONLY / 3 HOLD, never zero**, and are unauthenticated offline HUMAN diagnostics. A saved CSV does not grant permission to scan, dispatch, deploy, release or claim remediation.

## Printable, script-free offline HTML reports

All three original local-file comparators now support opt-in `--format html`, alongside the unchanged default `json` and the terminal-friendly `text` format. Redirect stdout to a local file; the CLI does not invent a destination, write a report file itself, or contact a network endpoint:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cli_1513.py \
  --format html before.json after.json > single-lab-review.html

PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format html baseline-cohort.json candidate-cohort.json > cohort-lab-review.html

PYTHONPATH=src python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py \
  --format html old.json new.json > scored-lab-review.html
```

Open the resulting HTML file locally in a browser or print it to PDF using your browser's print dialog. The portable report has **no scripts, remote fonts, images or external assets**. Its Content-Security-Policy denies all network connections and permits only the SHA-256-pinned embedded stylesheet. It contains a summary of admitted anonymous scenario counts, source-flagged adverse metrics, source-reported unknown-coverage values above zero, per-metric flag frequencies and a print-friendly baseline/candidate/delta detail table for each admitted scenario. Cohort details use locally assigned anonymous ordinals, never the original scenario IDs; scored ground-truth descriptions, planted finding identifiers, targets, client identities, input paths and raw notes are not printed.

The HTML report also provides an anonymous **HUMAN follow-up index** before the scenario details. It sorts navigational links by reported nonzero scope/policy indicators, then source-reported adverse metric flags, then unknown coverage, and gives a fixed next human review question for each case. This order is only an inspection convenience, **not** a security severity, verified remediation decision, real staff assignment, or automated action. Source ordinals refer to the existing admitted comparison order even when the index is sorted.

The source-reported `coverage_unknown` metric remains separate **uncertainty**, not an invented regression. Cost/runtime and other informational metrics retain their original comparator flags. Rejected or inconsistent input prints a generic `HOLD` HTML report **without partial metrics or scenario details**. The HTML is unsigned and numeric values are unauthenticated source data; do not publish private lab outputs or interpret the report as remediation, real safety evidence, authorization or consent.

The program exit contract is unchanged for all formats: **2 for REVIEW_ONLY, 3 for HOLD, never zero**. Shell redirection can create a local file even when the command exits 3: inspect the displayed HOLD status instead of treating file existence as success. Four authority flags remain false; no new execution, dispatch, scan, grant, deployment or release permission is created.

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



## One-row-per-case HUMAN action queue

All three already-existing offline CLI entry points now accept `--format actions-csv`
without changing their default JSON, terminal text, printable HTML or
detailed metric CSV formats. The action CSV contains **one ordered row per
admitted anonymous case**, and the HTML follow-up table shares the same
deterministic review ranking:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cli_1513.py \
  --format actions-csv before.json after.json > actions-single.csv
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format actions-csv baseline-cohort.json candidate-cohort.json > actions-cohort.csv
PYTHONPATH=src python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py \
  --format actions-csv old.json new.json > actions-scored.csv
```

Priority means a HUMAN review grouping, **not security severity**: source-declared
nonzero scope/policy signals first, then source-reported adverse metrics,
unknown coverage, and finally source verification. Within a group, source
adverse flag count and declared unknown coverage determine order; original
anonymous ordinals break ties. Both ranking and suggested questions are fixed
software wording. No source IDs, network addresses, client names, input paths,
run IDs, free notes, per-metric values or original finding payloads are in
this privacy-minimal export. Original source ordinals and computed review
order are separate columns so the original report can be located manually.

Bad/inconsistent inputs yield a generic single `Input HOLD` row without
partial details. An otherwise admitted source with regressions is also
globally HOLD but contains reviewable rows with `input_admitted=true`; a
HOLD is never a production verdict. In every CSV row, authorization,
authenticated consent, dispatch, release and source provenance remain false.
Use owner-private storage; a human chooses sharing. Exit codes remain
2 REVIEW_ONLY / 3 HOLD (never 0), even when shell redirection created a file.
There is no network, scan, grant, dispatch or release behavior.


## Selective HUMAN handoff without hiding the full source count

The same three native offline CLI tools now also support an explicit
`--focus` only together with `--format actions-csv`. Accepted values:
`all` (default), `scope`, `adverse`, `unknown`, `source`.
Each selection works **only after the full original comparison has passed
input admission**, so filtering does not weaken source consistency gates.

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format actions-csv --focus unknown baseline-cohort.json candidate-cohort.json \
  > unknown-only-private.csv
```

The export includes `focus_filter`, `accepted_case_count` and
`selected_case_count` in every row, with original *global* HUMAN
review rank and stable anonymous source ordinal. Thus a subset cannot be
mistaken for a complete all-case queue. An admitted zero-match filter emits
an explicit one-row `No matching HUMAN cases` notice with `input_admitted=true`;
invalid or inconsistent original input instead emits `Input HOLD`
with `input_admitted=false`. A filter supplied with JSON, HTML, text or
detailed CSV output is rejected to a generic HOLD rather than being silently
ignored. The filter never grants authority, modifies source data, executes a
lab, contacts targets or distributes the file.


## Scriptless, printable selected HUMAN handoff

The three native offline comparison CLIs now also support `--format actions-html`.
It renders the **same source-minimal, ranked, focus-filtered HUMAN actions** as
`actions-csv`, but as a standalone printable browser file. Example:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format actions-html --focus unknown baseline-cohort.json candidate-cohort.json \
  > unknown-human-actions.html
```

There are no scripts, network connections, external fonts or images. The
Content-Security-Policy is deny-all except the SHA-256-pinned bundled
stylesheet. The printable page exposes only fixed HUMAN question wording,
global review rank, original anonymous case ordinal, reported adverse-flag
count, unknown coverage, original total accepted count, selected count and
the chosen focus. It never shows original scenario names, source paths,
client/target identities, notes, per-metric details or input file bytes.
CSV and HTML use the same complete-source-admission and selection function,
including distinct **Input HOLD** and **admitted but no matching case** states.

The file is unsigned and its source signals are unauthenticated. A restricted
view does not clear excluded cases or represent actual owner assignment,
verified findings, permission, remediation, consent or GO. Shell redirection
can still create a file when exit 3 indicates HOLD. Existing full diagnostic
HTML, detailed CSV, JSON and text remain unchanged.

## Machine-readable offline HUMAN question queue

All three native comparison CLIs also accept `--format actions-json`, with
the same `--focus all|scope|adverse|unknown|source` selector:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format actions-json --focus unknown baseline-cohort.json candidate-cohort.json \
  > unknown-human-questions.json
```

This **separate, non-executable JSON handoff** has a stable
`schema_version=1`, `report_type`, full-source `input_admitted`,
`source_status`, `focus_filter`, total admitted and selected case counts,
the original *global* HUMAN review rank, anonymous source ordinal,
fixed reviewer question, admitted adverse flag/unknown coverage values,
and explicit false authorization/consent/dispatch/release/source-authentication
fields. No original client, host, source IDs, input paths, notes, findings,
credential material or target details are emitted.

The `notice` is exactly `input_hold`, `no_matching_human_cases`
or `human_review_only`. A malformed or inconsistent input produces an
empty `human_review_questions` array and `input_admitted=false`;
a successful whole-source admission with no selected cases also produces an
empty array, but remains `input_admitted=true` with the full accepted count.
The existing CLI exits **3 HOLD** or **2 REVIEW_ONLY**, never zero. The JSON
file is unsigned and has no authenticated source provenance; do not interpret
a machine-readable question as a grant, task dispatch, client consent or
release approval. All other output formats and normal comparator JSON stay
unchanged.

## Offline efficiency observations (informational, not an approval)

The existing three single/cohort/scored comparison CLIs now expose
`--format efficiency-json` or `--format efficiency-html`. These
operate **only on the already-admitted completed lab comparisons**:
no additional records, target probes, credentials, execution, persisted
source, scanner, browser scripts or network activity.

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format efficiency-html baseline-cohort.json candidate-cohort.json \
  > private-efficiency.html
```

The standalone printable HTML uses bundled hash-pinned CSS with deny-all
CSP and contains anonymous case ordinals, source-reported runtime seconds
and compute cost USD, deltas, descriptive direction and percentage change.
The machine-readable JSON provides the same data, exact
`baseline_total`/`candidate_total`/`delta_total` values serialized as
**decimal strings** (avoids non-finite floating-point cohort sums), and
case counts reporting increases/decreases. Percentage change is explicitly
`null` when the original baseline is zero. Both are deterministic over a
complete admitted cohort; rejected/partial/invalid input emits only generic
`input_hold`, never partially processed metrics or identities.

Costs and duration remain **informational**, exactly as in original #1513.
There is no statistical significance estimate, workload normalization,
spending threshold or production verdict. Unknown source provenance and
independent human/security reviews remain unresolved; every authorization,
consent, dispatch and release flag is permanently false in JSON. HTML
presents the same prohibition in human language. Existing commands continue
to return exit 2 REVIEW_ONLY / exit 3 HOLD and default JSON stays unchanged.
`--focus` is reserved for HUMAN actions formats, never silently applied
to efficiency exports.

## Nonexclusive HUMAN focus — no hidden overlapping cases

A case can have several original source-reported signals at once. Earlier,
`--focus scope|adverse|unknown|source` matched **only its single highest
HUMAN priority label**. A scope-priority case with an adverse finding or
unknown coverage could be missing from the adverse/unknown export. This
was a visibility defect, not an authorization failure.

All three original comparison CLIs now filter using **every matching signal**:
`scope` matches a reported scope/policy violation present in the candidate;
`adverse` matches any source-reported regression; `unknown` matches
candidate unknown coverage greater than zero; `source` matches the
residual source-verification review group; `all` retains every admitted
case. For example, a single anonymous case with scope, adverse and unknown
signals appears in all three corresponding filtered handoffs, but still
has just one original global HUMAN rank and **Scope/policy** as its highest
priority label. Filter counts can overlap and must never be summed into
a total case count.

The actions CSV, JSON and printable HTML now show the fixed
`matching_focus_signals` for each selected case; the CSV uses a safe
pipe-separated fixed-value field. Full-source admission, the original
metric comparator, rank/ordinal stability, invalid-input HOLD and no-match
distinction are unchanged. No raw IDs, target/client names or notes are
introduced, and no real consent, source authentication, dispatch, scan,
release or HUMAN GO is inferred.
