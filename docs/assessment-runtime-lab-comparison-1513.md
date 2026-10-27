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

This isolated test job is diagnostic only. Even on the named permanent VPS, its narrow comparator tests are **not** the canonical full-project runner/CI gate. Full-project exact-head CI, independent security/privacy, verified client+operator consent, revocation-at-use and explicit HUMAN GO remain required. **Never merge/deploy based on this comparator.**

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

## Exact source-head named-VPS regression gate

The dedicated assessment-runtime Python matrix requests the canonical
LightUp CI permanent-VPS runner labels `[self-hosted, zcloud, vps]`.
A prior attempt using the preflight label set `[self-hosted, lightup, vps]`
landed on disposable runner `vm-7eb5ee16-lightup`, not the permanent VPS;
the hostname guard correctly failed on both Python jobs before checkout.
The guard therefore still requires `hostname` exactly `vps-bb300bba`,
and the job checks out the immutable PR-head commit instead of
GitHub's temporary pull-request merge ref. The checkout assertion compares
`git rev-parse HEAD` with the immutable event head SHA **before** its offline
checks. This is only an isolated comparator diagnostic; it does **not** replace
the separately required complete LightUp CI/preflight, independent reviewer,
security/privacy, actual consent/revocation or explicit HUMAN GO.

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

In **all four** printable offline HUMAN report views (comparison, selected questions, resource observations and full bundle), `REVIEW_ONLY` uses the same amber **Human review required** badge; `HOLD` uses the same red **Source status: HOLD** badge. Advisory context such as **INFORMATIONAL ONLY** remains visible and cannot replace the source status. A no-adverse case explicitly says **not approval**. The fixed HTML labels are escaped and exposed consistently to assistive technology. Status computation, source flags, metrics, script-free CSP and zero authority remain unchanged.

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
candidate unknown coverage greater than zero; `source` matches **every
admitted, unauthenticated source case** (including scope/adverse/unknown
priority cases); `all` retains every admitted case. For example, a single anonymous case with scope, adverse and unknown
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

## Shared fail-closed CLI options (all three entry points)

All three original single-case, cohort and scored-cohort tools use one
stdlib-only `assessment_runtime_cli_options_1513.py` parser. The accepted
`--format` values are JSON (default), text, HTML, detailed CSV,
`actions-csv`, `actions-html`, `actions-json`,
`efficiency-json`, and `efficiency-html`. The optional
`--focus all|scope|adverse|unknown|source` is **only accepted** for
the three HUMAN `actions-*` formats.

Previously the individual parsers silently **accepted and ignored**
`--focus` alongside `efficiency-json` and `efficiency-html`, making an
operator believe the resource report was filtered when it was not.
Now invalid combinations, duplicate flags, non-string API arguments, unknown
formats or missing values produce a generic full-input **HOLD** (exit 3),
never a successful but misleading filtered report. A syntactically valid
`--format efficiency-json` with no focus still works unchanged.
For example:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format efficiency-json --focus unknown before.json after.json
# generic HOLD; resource reports cannot consume focus
```

This parser never reads local source bytes itself, prints a target or
authorization, invokes a scanner, dispatches a worker, writes a report
file, changes a grant or weakens existing scope/CI checks. Admitted
comparisons retain their original full-source parser, status
(`2 REVIEW_ONLY` / `3 HOLD`), source-minimal outputs and permanently
false authority fields. Source validation, owner approval and HUMAN GO
are still separate release gates.

## Complete unauthenticated source review and filter coverage

Every admitted lab comparison remains **source-provenance unauthenticated**.
An earlier `--focus source` export selected only cases whose highest
priority label was `Source verification`; it omitted unauthenticated
sources with reported scope/policy, adverse or unknown-coverage signals.
Those cases still need original source-owner verification. The corrected
`source` filter now includes **all admitted cases**, independently of
their primary review group. It preserves each original global rank,
anonymous case ordinal, priority group and source-reported signal counts.

Focused `actions-csv`, `actions-json` and `actions-html` exports now
ask the **selected signal's fixed HUMAN question**, even if a different
primary group has higher rank. With `--focus all`, the existing primary
group question remains unchanged. No prompt or field embeds untrusted
source text. Selection remains informational, not a completed verification.

Each actions format now explicitly reports `excluded_case_count`, equal
to `accepted_case_count - selected_case_count`. Zero excluded cases for
`--focus source` means every admitted unauthenticated case is **visible
for review**, not verified, cleared, consented to or safe for execution.
Scope/adverse/unknown groups overlap by design; excluded counts are per
view and must not be combined across exports. Input HOLD reports
`0/0/0` admitted/selected/excluded and cannot masquerade as a verified
empty source; a valid no-match view reports its complete accepted and
excluded counts. All authorization, consent, dispatch, release and source
authentication fields remain false. This is still Incubate M3/M7
PLAN/LAB ONLY until independent owner/security/privacy/HUMAN GO gates.

## Cohort-wide replay rejection (original #1513 comparison)

In both the unscored and ground-truth-scored offline cohort comparators,
each admitted source record must have a **unique `record_id` within its
cohort**. The two sides also must have **disjoint record IDs and run IDs
across every scenario**, not merely different identifiers for each matching
scenario pair. Reusing baseline case A's run or record as candidate case B
is a replay of existing evidence, not an independent benchmark comparison:
the complete cohort now returns generic `HOLD` with **no partial case
details**, and never runs a scanner or contacts a target.

Distinct scenario records are still allowed to share one `run_id`
**within the same side**, as is normal for a batch. All comparisons
continue to require identical canonical scenario sets, validated lab-only
inputs and independent paired source records; informative runtime/cost
observations are not new authority. Rejected source IDs, original client,
target, record details and input paths remain private. This check does
**not** authenticate any record or replace original source-owner evidence,
independent review or explicit HUMAN GO.

## Source-minimal full-metric JSON review (opt-in)

All three original offline entry points also accept
`--format review-json`. This is an **additional** versioned, machine-readable
local handoff; their existing default `--format json` response is unchanged.
The new output covers every comparator-admitted metric of every admitted case
using anonymous 1-based `scenario_ordinal` and the fixed comparison names,
with baseline, candidate, signed delta, source adverse flags and
source-reported unknown coverage.

The envelope contains `schema_version=1`, `report_type`
(`single_case`, `cohort`, `scored_cohort`), `source_status`,
`input_admitted`, `notice`, `accepted_case_count`, and `cases`.
Every case carries its own `source_status` and
`source_adverse_metric_count`; an admitted **adverse-metric HOLD** still
includes the **complete** original comparison for HUMAN assessment. A rejected
or inconsistent whole-input **HOLD** yields
`input_admitted=false`, `notice=input_hold`, `cases=[]` and zero case
count; nothing from a partial cohort is exported.

The export omits original scenario, record and run IDs, input paths, targets,
clients, freeform text, provenance identifiers and source comments. All
`authorized`, `consent_verified`, `dispatch_allowed`,
`release_allowed` and `source_provenance_authenticated` fields stay
**false**. The status is **source-reported only**, never independently
verified; no consent, remediation, grant, deployment or HUMAN GO is implied.
The `--focus` option remains valid **only** with `actions-*` formats,
including for this unfiltered full-metric export.

For example, with two previously completed local lab packets:

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cli_1513.py \
  --format review-json baseline.json candidate.json
# exit 2: REVIEW_ONLY; exit 3: HOLD (including valid adverse metrics)
```

## Complete cohort-level metric movement in the anonymous JSON handoff

The `review-json` envelope now also provides a deterministic `metric_summary`
for the same **full admitted** source population. Every canonical metric has
one entry with `observed_case_count`,
`source_regression_case_count`, and the number of cases where the raw
candidate value is `higher`, `lower` or `equal` to the baseline.
Unknown-coverage-positive counts are reported separately; top-level
`source_adverse_case_count` and
`source_unknown_coverage_case_count` show **how many distinct cases**
need attention even when several metric flags overlap in one case.

These are **not** weighted scores, averages, cost approvals or regression
verdicts. Higher/lower is purely numeric direction; interpretation depends
on the original metric (e.g. higher scope violations is adverse, higher
assessed coverage may be positive, higher runtime is informational).
The source-reported flags are carried through unchanged.

For a rejected or inconsistent whole-input HOLD, the envelope emits
`cases=[]`, `metric_summary=[]`, and all case counts zero, without
partial cohort disclosure. Structural anomalies such as missing, duplicate
or unknown metric names fail closed in this optional exporter. The format
is an additive extension to the new opt-in `review-json` surface;
the three CLIs' default JSON output remains unchanged. All authority,
consent, dispatch, release and source-authentication fields remain false;
source-owner and independent HUMAN GO gates remain required.

## Unified offline review bundle (opt-in)

Each original local-only assessment-runtime CLI also accepts
`--format review-bundle-json`. This returns **one** deterministic JSON
document for the same two explicitly supplied finished-lab inputs.
The three nested readouts are computed from the **same admitted comparison
result**, without re-reading, rescanning or changing a source record:

- `metric_review`: complete anonymous original per-case benchmark deltas,
  canonical cohort metric movement and adverse/unknown case counts.
- `human_actions`: the complete (`focus=all`) sorted HUMAN question
  selection, with original anonymous scenario ordinals and no source IDs.
- `resource_observations`: per-case and aggregate runtime/tool/cost changes,
  **informational only**, never budget, release or deployment approval.

The parent includes `schema_version=1`, `report_type`,
`source_status`, `input_admitted`, `notice` and
`accepted_case_count`. All three components must agree on report type,
status and the **complete case count**; the HUMAN selection must contain
every admitted case. If any component rejects or disagrees, the parent
fails closed: `source_status=HOLD`, `input_admitted=false`,
`accepted_case_count=0` and all three nested payloads `null`.
A valid **adverse-metric HOLD** with complete admitted cases is still
visible in full, and requires HUMAN review.

This format deliberately cannot take `--focus`: using it would hide
cases while implying a complete dossier; use separate `actions-*`
exports for explicit focus views instead. Existing formats, their
default responses and exit codes remain unchanged. It is a portable
**unsigned, unauthenticated offline diagnostic**, never an authorization,
release decision or a real scan instruction. The parent and each nested
section explicitly keep source authentication, consent, authority,
dispatch and release false.

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format review-bundle-json old-cohort.json new-cohort.json
# 2 REVIEW_ONLY / 3 HOLD; only local already-recorded lab packets are read
```

## Printable offline complete HUMAN review bundle

The three already-existing local-only CLI entry points now also accept
`--format review-bundle-html`. It renders the **exact same admitted**
`review-bundle-json` source once as a self-contained, print-friendly HTML
document: cohortwide canonical metric movement table, the full
source-minimal HUMAN question queue, observational runtime/cost totals,
and **every** fixed canonical metric for **every** admitted anonymous
case (not a selectively filtered view). The ranked HUMAN queue links each
admitted anonymous case ordinal directly to its full metric detail, with a
return link back to the questions. The question queue also lists the
exact **canonical source-flagged metric labels** for each case alongside
the adverse-flag count; these fixed, escaped labels disclose no original
source identifiers or freeform evidence, and are neither severity ratings
nor independent finding verification. This works for the bounded
64-scenario cohort without script or external navigation; links are fixed
local fragments derived only from admitted numeric ordinals, never source
identifiers. The HTML displays a clear
`REVIEW_ONLY` or `HOLD` badge, all five false authority/provenance flags
and the absence of independent proof or HUMAN GO.

Whole-input admission/consistency HOLD never emits partially admitted
scenarios, metric tables, questions or resource rows; it shows only a
generic HOLD explanation. Valid source-adverse HOLD retains its complete
comparison for HUMAN scrutiny. Fixed headings and HTML escaping protect
all rendered numeric/string cells. The document embeds the existing
local-only stylesheet behind an exact SHA-256 CSP style hash, disallows
scripts, connections, external assets, forms and frames, and does not
contain source scenario/record/run IDs, targets, clients, paths or freeform
evidence.

This is a **review artifact**, not authenticated provenance, a security
finding, dispatch approval, consent verification, cost authorization or
release decision. It does not modify inputs, run scanning tools, write
source files or transmit browser data. The original JSON/text/CSV/HTML
formats and default outputs remain unchanged. The complete dossier rejects
`--focus` to prevent accidental hiding of relevant admitted cases.

```sh
PYTHONPATH=src python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py \
  --format review-bundle-html baseline-scored.json candidate-scored.json \
  > private-review.html
# Only use on already-recorded, locally supplied isolated-lab inputs.
# Exit 2 means REVIEW_ONLY, exit 3 means HOLD. Neither permits a scan.
```

## Cross-section case alignment in the complete HUMAN review bundle

The opt-in `review-bundle-json` and `review-bundle-html` formats now
**fail closed as a complete packet** if their three nested views diverge,
even if they report matching totals and source status. Admission requires
exactly one sequential anonymous ordinal for every metric and resource
case; HUMAN questions must cover the same ordinals, exactly once, with a
complete unique review rank. Each HUMAN adverse count, unknown-coverage
value, scope/policy indicator, fixed primary review group and full signal
selection must match the corresponding case's canonical metric records.
The ranked HUMAN question rows must also be in exactly the canonical order
reconstructed from those metric records: scope/policy signals first,
source-adverse metrics next, unknown coverage next, and source verification
last; higher adverse counts, then unknown-coverage counts, then original
anonymous ordinal break ties. Merely supplying unique rank numbers cannot
demote a scope/policy case or silently reorder the offline review desk.
Each case's source-reported status must also agree **exactly** with its
adverse flag count: `HOLD` only with adverse metrics, `REVIEW_ONLY`
only without them. No internally contradictory source case may be
exported as admitted, including when a transferred JSON inspector would
reject it later. The per-case runtime/cost baseline, candidate and raw delta must match
that exact metric case as decimal values. This prevents an otherwise
plausible but misaligned handoff from assigning one case's HUMAN action or
cost observation to another case. A failed check returns generic
`HOLD`, all nested payloads `null` and zero admitted cases; no partial
metrics or original source identifiers are exposed. Valid adverse-metric
`HOLD` remains fully available for independent HUMAN scrutiny.

The script-free HTML tables also correctly detect empty generator-backed
row sets, showing a fixed no-admitted-rows notice rather than a misleading
empty table. No change to input readers, original comparator, default
formats, statuses, dispatch, permissions, targets, runner ownership or
independent HUMAN review gates. Ordinals are anonymous local display keys,
**not** source authentication or operator/client consent.

## Full-source metric and resource summary reconciliation

The complete offline HUMAN dossier now independently reconciles every
aggregate number to **all** admitted anonymous case records before it is
shown or exported. For each fixed canonical metric it checks the unique
summary entry, complete case count, source-adverse flag count, raw
candidate-higher/lower/equal movement and unknown-coverage flags; it also
checks the cohortwide adverse/unknown case totals. The **aggregate** source status must match the entire admitted
population in both directions: at least one adverse case requires
`HOLD`; zero adverse cases requires `REVIEW_ONLY`. Previously only
the first contradiction was rejected. The original comparator is
unchanged, and neither status supplies human authorization.

The resource section must contain precisely the expected runtime and cost
metrics. Each case's decimal delta, direction and percentage observation
must agree with its actual baseline/candidate. Cohort-level baseline,
candidate, delta and increase/decrease counts are reconstructed from the
same admitted case rows with exact Decimal arithmetic. If any metric or
resource rollup drifts, the **entire** bundle becomes generic `HOLD`
with zero accepted cases and no nested payloads. A complete admitted
source-adverse `HOLD` remains visible for independent HUMAN review.

This catches misleading aggregate totals without adding score thresholds,
new scans, network access, source identities, release decisions, worker
scheduling or authorization. The default comparison formats and original
owner workflows stay unchanged; unsigned source reports still need
source-owner, independent security/privacy, consent and HUMAN GO review.

## Safe local intake of a previously exported complete HUMAN review bundle

A new opt-in, stdlib-only tool
`scripts/assessment_runtime_review_bundle_inspect_cli_1513.py`
accepts **one already-existing local `review-bundle-json` file**. It
re-checks the nested packet after transfer to a HUMAN reviewer, rather
than assuming a JSON file is trustworthy merely because it parses.
It is a separate read-only inspector; it does not re-run the original
comparison, contact an asset, open a network connection, trigger a
handler, validate consent or release anything.

The inspector rejects malformed JSON, duplicate JSON keys, non-finite
numbers, unknown top-level fields, incompatible schema/status/flags,
unsafe authority booleans, incomplete case/question/resource
populations, altered fixed HUMAN question text, unexpected numeric
types, cross-section ordinal drift, impossible original metric value
classes/ranges, mismatched numeric deltas, contradictory per-case
regression flags or source case statuses, incorrect metric movement
summaries and corrupted resource/decimal totals. Values are checked
against the comparator's fixed local rules, including **source-semantic
case cardinality** (one standalone case or 1–64 cohort cases) and **top-level
HOLD/REVIEW_ONLY consistency** with the full admitted population's adverse
metric flags. An internally aligned but impossible standalone multi-case
packet or contradicted status is rejected atomically as anonymous HOLD.
These checks cannot establish source provenance or detect a deliberately
fabricated, self-consistent packet. A 4 MiB hard input cap bounds memory before JSON decoding; the admitted
schema permits only 1–64 cases with fixed canonical metric fields. Every
transferred resource decimal field is also restricted to 1–1024 characters
and a finite adjusted base-10 exponent between -700 and +700 before
arithmetic; these bounds cover the producer's finite Python-float values,
its exact 64-case Decimal totals and percentage readouts. This prevents
unbounded mantissa/exponent work in imported numeric strings without
adding any approval semantics. Oversized or extreme-value bundles are
rejected as generic no-data HOLD, without paths or payload echo. The local-file reader requires Linux-style secure
file-descriptor primitives (`O_NOFOLLOW`, `O_DIRECTORY`, `O_PATH`, and
`/proc/self/fd`): it pins each directory component, rejects symlinks in
**every** ancestor, rejects `.`/`..` traversal and non-regular files,
opens the already-pinned inode without blocking on FIFO/device swaps,
and compares inode/size/timestamps before and after the bounded read.
On unsupported systems or when a file changes during intake, it emits
generic `HOLD` without echoing local paths or original payloads.

Output is a fixed, source-minimal JSON record with
`format_consistent`, original source-reported `source_status`,
`input_admitted`, anonymous case count and **five permanently false
authority/provenance fields**. Malformed input produces an atomic
`HOLD` with zero cases; an originally rejected generic HOLD remains
a HOLD. An admitted source-adverse HOLD can be structurally consistent
but **must not** be mistaken for clearance. Exit codes preserve the
original local comparison convention: `2` for consistent
`REVIEW_ONLY`, `3` for any HOLD or invalid artifact.

```sh
PYTHONPATH=src python scripts/assessment_runtime_compare_cohort_cli_1513.py \
  --format review-bundle-json old-lab.json new-lab.json > private-bundle.json
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  private-bundle.json
# The second command reads only that existing local JSON file.
# format_consistent=true is STRUCTURE ONLY, not cryptographic integrity,
# authenticated source provenance, consent, authorization or HUMAN GO.
```

The original compact JSON stdout stays the default for tooling. For
a person reviewing the **already-received** packet, the same inspector
also has two opt-in, source-minimal receipts:

```sh
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  --format text private-bundle.json
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  --format html private-bundle.json > offline-review-receipt.html
```

The terminal text and responsive printable HTML use **only the fixed
structural result**, never original evidence, anonymous question text,
input paths, targets or saved records. The HTML is script-free,
self-contained and enforces a restrictive CSP with a hash-pinned local
stylesheet. It separates packet consistency, source-reported
`HOLD`/`REVIEW_ONLY`, admitted-case count and mandatory HUMAN review.
No browser upload, external fonts/assets, forms, network access or
authorizing button. Invalid or unsafe local files create a
generic zero-case HOLD receipt in the original JSON/text/HTML formats,
a generic zero-case HOLD full page in bundle-HTML, and a fixed input_hold
row in bundle-CSV, and a source-free generic HOLD notice in bundle-MD. Exit codes remain
`2` for a structurally consistent source `REVIEW_ONLY`, otherwise
`3`; the receipt is never a completion certificate.

### Full offline HUMAN dossier from a received, validated JSON packet

For a reviewer who received **only** the complete private JSON bundle,
`--format bundle-html` now reconstructs the full, printable script-free
HUMAN dossier after **all** existing intake checks pass. It shows admitted
anonymous cases, canonical source-metric values and movement, fixed HUMAN
questions with case-detail links, and resource observations. The original
`--format html` remains a short, source-minimal structural receipt; it
does not silently reveal case details.

```sh
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  --format bundle-html private-bundle.json > received-full-human-review.html
```

Invalid, changed, digest-mismatched or internally inconsistent input
renders **only** a fixed generic HOLD page with zero metric/question rows.
The full view reuses the exported HTML's CSP-pinned local stylesheet,
fixed headings and HTML-escaped canonical values. Each anonymous case detail
also shows its **two admitted resource observations** (runtime seconds and
compute cost USD) with baseline, candidate, exact raw delta, percent change
or explicit zero-baseline N/A, and direction. Each case detail is linked from its HUMAN question; its return
link now jumps **back to that exact validated review-rank row** (not to the
top of the queue). The row and case are highlighted by the browser's
native fragment target without scripts or generated source identifiers.
The same navigation works in exported and locally received full HTML bundles. The full HTML also includes a **case-by-metric
source signal matrix** before resource totals: all admitted anonymous cases
in the already-reconciled HUMAN priority order, with each of the eleven
comparator-relevant coverage/quality/safety metrics marked SOURCE FLAG,
UNKNOWN coverage, or no source flag. Every case ordinal links to its full
numeric detail. A missing flag **does not mean safe or approved**; operational
runtime/cost values remain informational in the case detail. These are
descriptive, unauthenticated lab-only values, **never cost approval**; no
original IDs, paths, targets, private notes, uploads, scripts or external assets.
A complete, consistent source-reported HOLD still exposes its anonymous
review questions to a human, but neither report can establish authentic
source provenance, consent, source approval or HUMAN GO.

### Received HUMAN bundle as offline analysis CSV

The same fully inspected private JSON can also be exported to
`--format bundle-csv` for local spreadsheet or data-analysis workflows.
It emits a fixed-column CSV with **all** canonical anonymous cases:
the HUMAN question rows first in verified priority order, followed by each
case's exact source metric and two resource observations. After these
case-level rows, it appends a **source-wide reconciliation ledger**: one
`source_summary` row with admitted/adverse/unknown/HUMAN counts, one
`metric_summary` row for each canonical metric with observed/adverse and
higher/lower/equal/unknown-coverage counts, and two `resource_total` rows
with exact Decimal baseline/candidate/delta totals and increased/decreased
case counts. All summaries were independently reconciled with **every**
admitted case during intake, so they cannot silently disagree with the
detailed source rows. Case rows retain their anonymous ordinal; aggregate
rows use no case identifier. Every row carries source-reported status;
the fixed columns keep all five authority/provenance flags explicitly
`false`. No source IDs, paths,
free-form evidence, target names, URLs, credentials or real findings are
exported. It is still an unauthenticated observation, never a scan or
budget/release approval.

```sh
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  --format bundle-csv private-bundle.json > received-human-review.csv
# Exit 2 = source REVIEW_ONLY; 3 = HOLD. Neither grants permission.
```

Every JSON object, metric value, case ordinal, question rank and source flag
passes the **same** private-file, optional out-of-band SHA-256, schema and
cross-section reconciliation as `--format bundle-html` before any rows are
emitted. Decimal resource values, changes, percentage strings and source-wide
totals must additionally match the original exporter's exact
`str(Decimal)` spelling: equivalent but altered spellings such as leading
`+`, padded zeros, lowercase exponent notation, whitespace or Unicode
digits produce generic HOLD instead of silently entering HTML/CSV. This includes **cross-section exact-scale reconciliation**: the resource
baseline/candidate/delta cells must reproduce their paired canonical source
metric string conversions, and aggregate totals must reproduce the exact
Decimal summation/delta serialization. For example, changing an exported
`1.0` total or case delta to `1` is rejected even when both spellings
represent the same number. Resource percentages and directions remain checked
against the recomputed values as before. This is
structural-text consistency, **not** source authentication or cost approval. Detailed HTML and CSV now reuse the **same single bounded,
fully validated in-memory packet** used for the compact structural receipt:
no second JSON decode or duplicated source/rank arithmetic, and no change
to the atomic generic HOLD behavior, accepted source values, exit codes
or authorization flags. On rejection it returns only a fixed `input_hold` row with no case
data; no partial cohort is disclosed. CSV quoting handles delimiters;
all question text and labels are pre-defined, not source-controlled formulas.
For portability the export uses CRLF row endings and no external packages.

### Editable offline HUMAN checklist in Markdown

For an offline review handoff that a human can copy into a **regular Notion
page** or edit as a local text file, the same fully inspected private JSON can
now be rendered with `--format bundle-md`. The output is native Markdown:
the complete, independently reconciled HUMAN review queue comes first as
unchecked `- [ ]` items in source-priority order. Every unchecked question
now includes its **exact fixed source-flagged metric names** (or explicitly
none reported) plus the canonical baseline → candidate → raw-delta values
for **runtime seconds and compute cost USD**. These observations are
informational, never prioritization or spending authority. A source-wide
metric/resource movement ledger and all canonical per-case metric and cost
observations follow in the same HUMAN rank order. Every question is fixed
to its fully validated source metric case; no raw IDs, paths, URLs, evidence or
uncontrolled notes are imported. This creates **review prompts**, never
permissions or sign-off records.

```sh
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  --format bundle-md private-bundle.json > received-human-review.md
# Exit 2 = source REVIEW_ONLY; 3 = HOLD. Neither grants permission.
```

Every fully admitted receiving-side `bundle-html`, `bundle-csv`, or
`bundle-md` output now carries the SHA-256 of the **exact bounded JSON bytes
that the importer actually read and admitted**. HTML shows a local, script-free
receipt, Markdown puts it above the HUMAN questions, and CSV includes the
`received_json_sha256` column on its aggregate `source_summary` row without
moving the HUMAN-priority question rows. Three
exports from the same input therefore have a human-comparable fingerprint;
mismatched fingerprints mean their JSON inputs differ. The digest is computed
after the optional separately supplied `--expected-sha256` equality check;
it cannot authenticate the sender or validate source evidence, consent,
authority or release. Do not treat it as a signature or automatic sign-off.

Rejected, malformed, changed or digest-mismatched input produces a **fixed,
source-free HOLD** message with no checkboxes, metrics or case content.
An admitted source-reported HOLD does retain all anonymous HUMAN questions
for review but never becomes approval. No Markdown file is automatically
uploaded to Notion or to another service; transfer stays under human control.

For a transfer where the human reviewer already possesses a **separately
verified expected SHA-256** of the exact source JSON bytes, all six
receiving formats also accept opt-in `--expected-sha256` (exactly 64
hexadecimal characters). The hash check occurs **after** the symlink-
and race-hardened bounded read and **before** parsing/review. Incorrect,
missing, malformed or duplicated digest arguments, or changed file
bytes, result in the same generic no-data HOLD, with no expected or
actual digest echoed and no original path disclosed. Output schemas
and return codes do not change.

```sh
# KNOWN_SHA256 must arrive via a separately verified channel.
PYTHONPATH=src python scripts/assessment_runtime_review_bundle_inspect_cli_1513.py \
  --format html --expected-sha256 "$KNOWN_SHA256" private-bundle.json \
  > offline-review-receipt.html
```

A hash calculated from the received file **on the receiving computer**
does not prove anything about the sender; even an independently supplied
hash proves byte equality only, not who performed an assessment, whether
measurements were true, or any approval to run a future scan. The
provenance/consent/revocation/security/HUMAN gates are unchanged.

There is **no signature or trusted key** in this lab format: a fabricated
packet can be internally consistent. The inspection detects malformed,
misaligned or accidentally edited packets but cannot establish who
created one or whether source evidence was true. The original owners'
source, security/privacy, client/operator, revocation and HUMAN GO
gates remain required for anything outside offline review.

The hardened reader also rejects symlinked parent directories and
replaced or modified files **during** inspection. The earlier top-level
symlink-only check was insufficient against a raced ancestor path;
this is a file-input protection only and still cannot authenticate a
self-consistent but fabricated assessment result.
