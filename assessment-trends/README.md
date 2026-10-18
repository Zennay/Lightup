# LightUp Lab Trajectory — offline longitudinal analysis

**Current release boundary: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Work package [#1584](https://github.com/Zennay/Lightup/issues/1584). No main merge, deployment, release, target access, scan, grant, handler, retest, operator consent or security authority is implemented. Production requires separately authenticated client + operator consent (with action-time revocation), original #177/#182/#829 owner fixes, complete existing hosted and permanently registered named VPS exact-HEAD CI, independent security/privacy review and explicit HUMAN GO.

## Open and operate

Open standalone.html locally in a browser (no server required), or load index.html with the adjacent local style.css and app.js. The standalone file is built reproducibly with python3 assessment-trends/build_standalone.py using stdlib and a restrictive content-security policy with SHA-256-pinned inline CSS and JS. No HTTP clients, external scripts/fonts/images, browser storage, remote endpoints, filesystem scans or background worker.

1. From existing, separately obtained original [assessment-runtime #1513](https://github.com/Zennay/Lightup/pull/1515) exports, choose **3–12 original cohort comparator CLI JSON reports**, each at most **262,144 bytes**, in the display order you want. The selection order is not proven run chronology.
2. Each original report must have status, regressed_scenarios, comparisons and the four literal-false flags authorized, consent_verified, dispatch_allowed, release_allowed. Comparison records must have the original scenario_id, status, regressions, and all fifteen complete canonical metric changes. This tool rejects partial HOLD packets, single-case output, foreign schemas and changed baseline sets.
3. **Reorder reports after importing.** File-picker order cannot be trusted to reflect chronology. The workspace has explicit earlier/later controls which recalculate all trends and exports without new network calls. This is an unverified user-selected order.
4. All revisions must carry **exactly the same scenario IDs** and the same original baseline value for each metric of each scenario. Different baselines are not silently reconciled. A mismatched or malformed batch replaces nothing and shows a generic HOLD message.
5. Explore regressed-scenario counts for every metric and revision, persistent/newly emerged/recovered flags, and original baseline/candidate/delta aggregates. Performance/cost are informational rather than adverse. Enter optional discussion notes locally; these are deliberately never included in exports.
6. Inspect the anonymized per-case churn grid (source IDs remain internal, never exported). A source-driven human review register now prioritizes critical scope/policy, detection and other adverse metrics, shows persistent/emerging/recovered signal and permits a private discussion-stage selection without any actual assignment or verified remediation.
7. Export explicit aggregate-only CSV/JSON or print. Reports contain numeric aggregates, fixed metric names and relative positions only. They contain **no scenario names/IDs, raw original files, source filenames, network target metadata, customer identifiers, credentials, notes, SHA fingerprints or inferred authorization**. A report with no counted regressions still remains REVIEW_ONLY, never PASS/GO.

## Threat and provenance boundaries

- JSON is read with a bounded recursive parser which rejects duplicate keys (including escaped-key aliases), nonfinite values, unexpected fields, missing or duplicate scenarios, invalid metric types/ranges/deltas, inconsistent regression labels, wrong global verdict, reordered/missing scenario membership, changed baseline or any true/extra security claims. Import is **atomic**.
- Matching scenario IDs, stable baselines or improved scores do **not authenticate** original records, confirm that source files came from the LightUp CLI, prove common lab ground truth, imply remediation, verify consent, authorize a retest or establish any release decision.
- The reviewer's chosen sequence is not authenticated temporal data. We do not infer actual run timestamps, model provenance, real asset identities or causality. Source reports are *untrusted*, and no client secrets should be included.
- Up to 64 canonical source scenarios; 15 metric names; 3–12 reports. The browser runs locally without network or browser persistence. Downloaded reports require normal local privacy handling. The original input JSON remains in browser memory until **Forget** or page close.
- This workspace owns only new assessment-trends/ paths. Actively owned comparator PR #1515, reviewdesk PR #1576, scope-authorization, production app, original CI, scanners and runners remain untouched.

## Outputs

- **Heatmap:** count of affected source scenarios for each metric and user-ordered report position; persistent count across every report.
- **Case churn:** local ordinal labels (Case 01 etc.), per-revision count of regressed metric categories, persistent/emerged/recovered/changed filters. No original scenario labels are exported.
- **Trajectory:** selected metric's original baseline aggregate, candidate aggregate, delta, ever-regressed, emerged, recovered and persistent counts. This is source-reported pattern analysis only.
- **Review handoff:** version 2 aggregate JSON additionally contains fixed metric-name, aggregate pattern and self-reported local discussion-stage enums (no notes or identities), while CSV remains aggregate-only. Four false authority flags in JSON, and non-authorizing headers in CSV. No sensitive source identities or locally entered reviewer notes are exported.
- **Print:** a self-contained local brief without the file input or local notes. Export and print are deliberate user actions.

This is a separate complementary offline product, **not merged into** PR #1515 or PR #1576 and not a release gate.
