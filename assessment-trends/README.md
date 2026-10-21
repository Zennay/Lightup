# LightUp · Assessment Trends

INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. New-only workspace for issue #1584. It compares 3–12 already-completed canonical cohort-comparison JSON documents produced by the existing #1515 comparator. It does not create a cohort, invoke the comparator, run tests, access a target, call a handler or make a security decision.

## Open the product

Open standalone.html locally. For development, open index.html with its sibling app.js and style.css.

1. Select 3–12 original cohort snapshots in the order you want to display them. Each input is at most 256 KiB. The order is a manual display preference, not authenticated chronology.
2. The browser validates the exact canonical CLI output schema, duplicate-free JSON keys (including escaped aliases), the exact 15 metric shape, derived deltas, source-reported regression flags and four literal false authority flags.
3. All snapshots must have exactly the same original scenario set and exactly the same baseline for every (scenario_id, metric) pair. An invalid or partially matching batch is rejected atomically; a previous admitted workspace remains intact.
4. Explore the review-priority and persistence heatmap, anonymous scenario trajectories and candidate/delta/flag values across all manually selected slots. Persistent means the same scenario/metric has a source-reported adverse flag in at least two consecutive slots. This is a display calculation over untrusted reports, not a verified finding.
5. Review anonymous source-flag change events using manual slot, event-kind and static review-group filters. The paginated 100-row queue shows initially reported, newly reported, consecutive, reappeared and no-longer-reported flags. Jump from a row directly to its HUMAN commentary editor. Download strictly separate filtered anonymous event CSV/JSON; no original scenario IDs, filenames, hashes or private notes are included. A flag absent in a later manually selected slot is **never** proof of remediation.\n6. Save human commentary only in tab memory. Anonymous JSON, CSV, printable and script-free HTML brief omit original IDs, filenames, uploaded hashes, raw source JSON and note text. A separate, explicitly confirmed PRIVATE commentary export contains note text with only anonymous scenario ordinals and fixed false authority flags.
7. Forget all local data clears imported snapshots, saved commentary and scratch notes. No localStorage, cookies, IndexedDB, service worker, telemetry or network access is used.

## Accepted source schema

Each file is the already-produced JSON object from assessment_runtime_compare_cohort_cli_1513.py:

- Exact top-level keys: status, regressed_scenarios, comparisons, authorized, consent_verified, dispatch_allowed, release_allowed.
- Each comparisons[] item contains exact keys scenario_id, status, regressions, changes.
- Each changes[] item contains exact keys name, baseline, candidate, delta, regression, in the comparator's canonical 15-metric order.
- status is HOLD or REVIEW_ONLY; the status and regression arrays must agree with the imported source metric flags. All four authority flags must be literal false.
- Counters, scores, costs, finite values and candidate minus baseline = delta are bounded and reconciled. Scope/policy and findings metrics use the comparator's existing directionality; operations metrics are informational.

The input is treated as untrusted and unauthenticated. Matching scenario IDs or baseline numbers is not proof that source files, measurement claims, chronology or lab environments are authentic.

## Handoff

- Aggregate JSON: snapshot status/counts, per-metric flag counts and anonymous scenario-slot trajectories; no IDs, filenames, hashes or notes.
- Change-event CSV/JSON: filtered, anonymous, manual-order source-flag events, page-independent; no notes, original IDs or authority.\n- CSV: long-form numeric trajectory per anonymous scenario slot × metric × selected snapshot slot; all authority fields false.
- Script-free HTML: privacy-minimal aggregate summary including a per-manual-slot event-kind matrix (initial, first, consecutive, reappeared, no-longer-reported). Absence of a source flag is never fix proof. with a restrictive no-network CSP.
- PRIVATE commentary JSON: explicitly confirmed note handoff, not an anonymous artifact.

All outputs preserve REVIEW_ONLY / HOLD, fictional_demo_only, manual-order and false-authority declarations. Nothing in this app authorizes a scan, grant, dispatch, remediation, consent or release. Independent source-owner/security/privacy review, exact-head mandatory CI, current authenticated client/operator consent with action-time revocation and explicit HUMAN GO remain separate gates.

## Build

Run: python3 assessment-trends/build_standalone.py

The builder inlines the checked-in JS/CSS and pins their SHA-256 hashes in the standalone Content Security Policy. It is a packaging step, not a QA/test suite.
