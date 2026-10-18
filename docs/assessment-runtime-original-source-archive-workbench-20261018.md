# LightUp · Original Offline Assessment Workbench

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This branch physically composes held original assessment-runtime [PR #1621](https://github.com/Zennay/Lightup/pull/1621) with held independent Assessment Archive [PR #1622](https://github.com/Zennay/Lightup/pull/1622), without altering either original branch. This cannot authorize scans, release or deployment.

## Real source composition

The original unchanged Studio, Lineage Desk, Candidate Matrix, Review Desk and original read-only comparator sit in the same checkout as the independent Archive Studio, source-bound human follow-up, source history, human agenda and private coordination room.

The integration adds an operator CLI and a complete non-authorizing workflow: **original already-completed comparator sources → original review ZIP → private multi-source archive → browser Studio → exact-source human follow-up draft → private review-room ZIP**.

**Source ownership:** This child branch is based on original assessment composition SHA a7e020483e3010e2101446e83b60e1994ad34ef4, copying only the 14 independent assessment-archive files from HEAD 88126dc3597ca6be1a7f120a8e202a00008190ae. Other source owners' apps, original scripts/lightup_review.py, scope/consent/authorization/ToolExecutor, CI and all QA/test paths are unchanged. New paths are additive.

## Open original offline launchpad

From anywhere:

    python3 /path/to/Lightup/scripts/lightup_workbench.py workspace

Open the returned local file URL for assessment-workspace/composed-workbench.html. It links to the original local tools without a web server or scanning.

## One command for original completed benchmarks

For two previously completed original isolated lab benchmark-case JSON sources:

    python3 scripts/lightup_workbench.py compose /private/BASE-case.json /private/NEXT-case.json --output-dir /private/reviews --prefix review01

The chosen existing directory must be owner-only 0700, owned by the current user and not a symlink. All six destination names must be unused. The command reads only the two explicit original private case files, checks source bytes before/after the original comparator, and never invokes a lab runner.

On a valid original comparison with real metrics — REVIEW_ONLY (2), or HOLD (3) for actual measured regressions — it preserves **six** new fsynced exclusive mode-0600 artifacts:

- review01-original-review.zip — original source-rich source-owner comparator review pack.
- review01-original-comparison.json — **byte-identical original source-owner review-desk JSON**, including the actual REVIEW_ONLY/HOLD status and original cohort/case metric changes.
- review01-source-archive.json — canonical local pathless manifest for both source files, original comparison JSON and original private review ZIP.
- review01-archive-studio.html — self-contained, no-network private source-bound browser worklist.
- review01-human-followup.json — editable SHA-bound human planning choices.
- review01-review-room.zip — navigable private offline coordination room with human stages and Studio.

With already-completed original 1–64 case cohort JSON-array files add --cohort; this merely delegates to the original comparator's cohort format.

### Directly select multiple original completed cases, without manually bundling

One or more explicit original individual completed case JSONs can now be supplied
on *each* side, with up to 64 per side, using the original source-owner
cohort bundler and comparator, not a new homemade metric or scanner:

    python3 scripts/lightup_workbench.py compose       --baseline-case /private/BASE-1.json       --baseline-case /private/BASE-2.json       --candidate-case /private/NEXT-1.json       --candidate-case /private/NEXT-2.json       --output-dir /private/reviews --prefix batch01

The original existing bundler creates two canonical private cohort JSON arrays
inside the private staging area. Source inputs are byte-checked before/after
original bundling and once again before publication. The comparator uses these
**same canonical original arrays** as sources, so original ZIP source SHA,
canonical comparison JSON, archive, Studio and human review are linked without
changing the original source IDs, metrics or result semantics.

This form produces eight owner-private new outputs: the six listed above plus
batch01-source-baseline-cohort.json and batch01-source-candidate-cohort.json.
These two extra canonical arrays are published with their original private
scenario details and must not be treated as anonymous. The original HOLD
comparison and its reviewable source are preserved; no run, replay, scan,
model call, grant or assessment execution occurs.

Mixing positional/canonical input forms, --cohort and repeated --baseline-case
or --candidate-case is rejected. Repeated input paths, missing original cases
or the original bundler's source-validation HOLD also block the handoff.


The original comparator's source/metric semantics are retained unmodified. The integrated reader verifies original ZIP member names, its original manifest's precise source SHA-256 fingerprints, exact original review-desk JSON hash and all false permission flags. A **genuine HOLD caused by original measured regression is archived** for a human to inspect, and remains HOLD in both private manifest and review-room output; there is no silent conversion to REVIEW_ONLY. Malformed inputs, a comparator HOLD with no valid reviewable report, changed source bytes, occupied destinations or invalid original evidence are rejected without producing a misleading archive. HOLD is never clearance.

Private temporary staging builds all six outputs before final publication. A partial set of NEW files may remain if a later final publication fails, but no existing user path is overwritten; original case files remain read-only. Original completed source files and SHA indexes are private evidence; protect generated outputs.

## Complete original source-bound Review Desk human handoff

If the original browser Review Desk has already exported a human planning
JSON for the EXACT original source-rich seven-file review ZIP, complete the
existing source-owner follow-up workflow in a single private command:

    python3 scripts/lightup_workbench.py human-handoff /private/ORIGINAL-review.zip /private/SAVED-human-v2.json --output-dir /private/reviews --prefix human01

The adapter delegates first to the unchanged ORIGINAL attach implementation
for v1/v2 source-bound Review Desk planning admission, and then to the
unchanged ORIGINAL minimized human handoff exporter. It never creates an
original human planning decision or accepts a mismatched source. A genuine
original metric regression HOLD is kept as HOLD (exit 3), even when a valid
source-rich human follow-up packet is preserved for investigation.

Seven new private 0600 outputs are produced: original canonical comparison
JSON, annotated original source-rich ZIP, minimized original human ZIP,
four-source archive manifest, interactive private Studio, SHA-bound source
human coordination draft, and private review-room ZIP. All original records
and planning sources are re-observed before final publication. The original
comparison JSON is byte-identical to the original original review member,
so HOLD is retained through the archive. No existing source or output is
overwritten. Minimized original exports exclude scenario identifiers and
source hashes by the original source owner's rules.

Only existing original lab source and explicitly human-provided files are
opened. No new model, target, grant, authenticated consent, scan,
assessment or release action runs.

## Original Candidate Matrix preparation for multiple completed models

The composed product now also includes a single CLI to compare one ORIGINAL
already-completed lab cohort baseline against 2–12 explicit previously
completed candidate lab cohorts and package source-owner results into one
private, portable offline Candidate Matrix workspace:

    python3 scripts/lightup_workbench.py candidate-matrix /private/BASE-cohort.json --candidate /private/A-cohort.json --candidate /private/B-cohort.json --output-dir /private/reviews --prefix model-selection

This delegates every pair to the UNCHANGED original LightUp canonical cohort
comparator and emits canonical source-owner desk-json reports. It pins the
ORIGINAL Candidate Matrix single-file browser asset to its exact SHA-256
5e14ac1bffffa46007dfcbff7a31905abeda93f2d4547021daf0565ecc4fc4df,
and packages that exact unmodified browser alongside numbered original
candidate comparison outputs, original report byte fingerprints, a private
original baseline digest and a plain README. No original lab case array or
raw target output is copied into the Matrix ZIP, although comparison reports
themselves may contain sensitive scenario identities.

Private outputs include numbered candidate-01..12 JSON reports, one indexed
private JSON receipt and an original Candidate Matrix ZIP. Open the ZIP only
in a trusted private local extraction directory, open standalone.html,
then select all numbered reports/candidate-XX.json files in the original
browser's existing file picker. The source Matrix remains responsible for
its own canonical cross-candidate schema, scenario and baseline consistency
checks and cannot issue a release GO.

### Original historical Trends in the SAME candidate package

The unchanged original [Longitudinal Trends PR #1585](https://github.com/Zennay/Lightup/pull/1585)
at exact head c8e44767c7a24bd0575988fed98c836872f98cb0 is now physically
available under its six original assessment-trends/ files in the same source
checkout, with no source-owner modifications. Original standalone HTML SHA-256
b8d30f90d3548e8de8f97cfa58631314a8856e9e2e5f8f904125aa235fa0585f.

For 3–12 original finished candidate cohort revisions, add --include-trends:

    python3 scripts/lightup_workbench.py candidate-matrix /private/BASE-cohort.json --candidate /private/R1.json --candidate /private/R2.json --candidate /private/R3.json --include-trends --output-dir /private/reviews --prefix historical-cohorts

The owner-private ZIP contains the EXACT original Candidate Matrix and
Longitudinal Trends standalone apps, a script-free local index.html, the
original numbered canonical comparison JSON files and a source-byte
fingerprint index. Open index.html only after trusted private extraction;
each app requires an explicit original browser file import of the numbered
reports in intended chronological order. Nothing starts a target, performs
a new model invocation, invents metrics, changes the original source or
issues a security/release GO. Measured original HOLD remains HOLD.

All input cohorts are explicitly selected owner-private regular files,
byte-checked before and after each original comparison and again before
publication. Any missing/duplicate source, invalid report, source content
change, unsupported original Matrix asset or occupied destination causes
HOLD. Genuine original per-candidate metric regressions remain HOLD in the
generated private reports and aggregate batch exit (3) while still
preserving original source-review evidence for the original human reviewer.
This remains only an offline discussion instrument: no new model,
scan, target contact, trading of source metrics, client grant or release.

## Original comparator and independent archive from one CLI

Original source-owner behavior retained:

    python3 scripts/lightup_workbench.py review compare BASE.json NEXT.json --format review-pack --output /private/NEW.zip
    python3 scripts/lightup_workbench.py review inspect /private/NEW.zip
    python3 scripts/lightup_workbench.py review attach ORIGINAL.zip HUMAN.json --output /private/NEW-annotated.zip
    python3 scripts/lightup_workbench.py review handoff ANNOTATED.zip --output /private/NEW-minimal.zip

Source-bound archive and human coordination from the same entrypoint:

    python3 scripts/lightup_workbench.py archive capture BASE.json NEXT.json --output /private/NEW-archive.json
    python3 scripts/lightup_workbench.py studio --manifest /private/NEW-archive.json --output /private/NEW-studio.html
    python3 scripts/lightup_workbench.py followup draft --manifest /private/NEW-archive.json --output /private/NEW-human.json
    python3 scripts/lightup_workbench.py agenda --manifest /private/NEW-archive.json --choices /private/NEW-human.json --as-of 2026-10-18 --output /private/NEW-agenda.html
    python3 scripts/lightup_workbench.py packet --manifest /private/NEW-archive.json --choices /private/NEW-human.json --include-studio --output /private/NEW-room.zip
    python3 scripts/lightup_workbench.py packet-inspect /private/NEW-room.zip
    python3 scripts/lightup_workbench.py console

A human cannot issue GO by editing a private planning draft. No command discovers a target, calls a model or target, grants consent, scans assets, changes source metrics or bypasses CI.

## Explicit source-path no-follow boundary

The composed wrappers pass the user-selected absolute lexical source path
directly to the existing bounded regular-file O_NOFOLLOW reader, **before**
any original comparator/bundler or human handoff. They do not resolve a
user-selected final-component symlink and then mistakenly read its target.
Canonical Python source snapshot and original source-owner review controls
remain unchanged. This is read-only source intake, not a provenance,
ownership or consent attestation.

## Mandatory release gates

**DRAFT/HOLD, do not merge into main or deploy.** Existing exact-head hosted plus permanently named VPS CI, original source-owner acceptance, independent security/privacy, genuinely authenticated separate client and operator permissions with action-time revocation as applicable, and explicit HUMAN GO remain mandatory. The known original scope #301 acceptance failure is not modified or circumvented. No QA suites were created or run.
