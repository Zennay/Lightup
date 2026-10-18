# LightUp · Offline Lab Candidate Matrix

**Stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** [Product issue #1591](https://github.com/Zennay/Lightup/issues/1591). This is a private offline human discussion instrument, **not an assessment scanner, production release recommendation, client consent verifier, safety verdict or grant service**. The four output fields `authorized`, `consent_verified`, `dispatch_allowed` and `release_allowed` are always false.

## Open immediately

Download [standalone.html](standalone.html) and open it in a modern local browser. There are no external dependencies, HTTP calls, install steps, accounts, browser storage, cookies, persistence, registered service workers, target interaction, execution commands or backend. `index.html` also works alongside `app.js` and `style.css`. The self-contained release is rebuilt by `python3 assessment-candidates/build_standalone.py` using Python's standard library, with a restrictive CSP hashing the original inline script and CSS.

Click **Explore fictional demo** to view four made-up candidate outputs for four invented lab cases. They are unmistakably labeled fictional in the screen and exported JSON, and no assessment is performed.

## Compare real *pre-existing* offline lab summaries

1. In the existing separate assessment-runtime comparator [draft PR #1515](https://github.com/Zennay/Lightup/pull/1515), use its own opt-in cohort CLI to create already-finished offline output. This matrix **never invokes the CLI**, imports source data only, and does not validate original source authenticity.
2. In this independent workspace, select **2–12** locally stored canonical cohort comparison JSON documents, up to 262,144 bytes each. They must share exactly the same 1–64 canonical scenario IDs and all fifteen original baseline values for each scenario; candidate values must be distinct. Original output has exactly: `status`, `regressed_scenarios`, `comparisons`, and all four literal-false authority fields. Each comparison has exactly `scenario_id`, `status`, `regressions`, `changes`. Each change has exactly `name`, `baseline`, `candidate`, `delta`, `regression`. Reports carrying incomplete HOLD records or unknown authority fields are rejected. All files are parsed and checked as one transaction before any existing workspace is replaced.
3. Explore source-report scorecards. Inspect critical scope/policy figures **separately** from performance/cost. The original source can report HOLD due to one or more metric regressions; **neither HOLD nor REVIEW_ONLY is an execution authority**. Candidate order is for display only, not authenticated run chronology.
4. Inspect the full **15-metric cross-candidate aggregate matrix**, preserving the exact original shared baseline for each source metric and reporting independently the adverse case count per candidate. Select any two distinct candidates to view explicit source-reported numerical changes (second minus first). This is not a newly conducted assessment or original source classification.
5. Configure six **hypothetical human discussion thresholds**: max scope and policy violations, minimum mean evidence-quality and assessed-coverage floors, optional max aggregate runtime and cost. Thresholds only classify whether an analyst should discuss results; clearing them does not mean safe or releasable. Invalid inputs make the threshold/tradeoff/export view HOLD, never export stale values.
6. Select any subset of four illustrative Pareto comparison dimensions (quality, coverage, runtime, cost). Undominated candidates are *only numerically undominated under these user-selected, untrusted lab metrics*. Safety/adverse source flags are never traded away or incorporated into permission.
7. Select **Lab case 01…64** and any of the original **15 metrics** to inspect baseline, candidate value, delta and reported regression across the same anonymized case. Original case IDs are not displayed or exported.
8. Export aggregate-only CSV or JSON, or print a private discussion view. Exports use numbered candidate slots, bounded aggregate numerical metrics, fixed original metric names, optional thresholds, false authority flags and the demo provenance marker (JSON). **No source filenames, original scenario IDs/names, URLs, hosts, client identities, credentials, raw original input bytes, free-text notes or hashes are exported.** Save exported local files in a private, appropriately protected location.

**Reset:** **Forget all** immediately clears source records from the app's in-memory state. Closing the browser clears its page instance; there is no background state, persistence or autosave. Failed import never replaces previously imported sources.

## Fail-closed semantics

- Strict recursive JSON reader rejects duplicate keys even through JSON unicode escapes, malformed/overlong nesting, excessive entries, nonfinite numbers and invalid UTF-8.
- Enforces exact object-key sets, literal-false authority flags, max 12 source files, one to 64 scenarios per report, safe nonnegative integer count metrics, bounded float scoring/cost/time, delta arithmetic coherence, regression direction/flag coherence, whole-report HOLD status coherence and exact cross-report shared baseline/scenario membership.
- Rejects repeated candidate numeric snapshots, zero-length or oversized files, missing/incompatible metrics or inconsistent case identity, while leaving the previous in-memory workspace unchanged.
- Text originating in lab inputs is never interpolated as HTML, exported or presented as real authority; user-facing cases use local ordinal numbers.
- No reading disk other than explicitly picked files, and no DNS or HTTP APIs. CSP `connect-src 'none'`, `default-src 'none'` and SHA-256 hashes restrict the standalone artifact.
- Stage remains **DRAFT/HOLD**. Original source-owner #177/#182/#829 repairs, independently authenticated client and operator consent plus revocation-at-action, complete existing exact-HEAD hosted and permanently named registered VPS CI, independent privacy/security review and explicit HUMAN GO remain unfulfilled release gates. **Do not merge or deploy to production.**

## Isolation and source ownership

This independent branch changes exclusively **new** files in `assessment-candidates/`. It does not edit or claim the comparator #1515, reviewdesk #1576, trajectory #1585, production runtime, domain, policies, webapp, scanner, service, CI, self-hosted runner or any other worker's files. The standalone works with original #1515 JSON schemas but does not import or copy the actively owned source implementation. No QA/regression suites have been written or run under the 17 October execution policy.
