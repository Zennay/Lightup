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

The chosen existing directory must be owner-only 0700, owned by the current user and not a symlink. All five destination names must be unused. The command reads only the two explicit original private case files, checks source bytes before/after the original comparator, and never invokes a lab runner.

On original REVIEW_ONLY (2), it produces five new fsynced exclusive mode-0600 artifacts:

- review01-original-review.zip — original source-rich source-owner comparator review pack.
- review01-source-archive.json — canonical local pathless manifest for both source files and original report ZIP.
- review01-archive-studio.html — self-contained, no-network private source-bound browser worklist.
- review01-human-followup.json — editable SHA-bound human planning choices.
- review01-review-room.zip — navigable private offline coordination room with human stages and Studio.

With already-completed original 1–64 case cohort JSON-array files add --cohort; this merely delegates to the original comparator's cohort format.

The original comparator's source/metric semantics are retained unmodified. If it returns HOLD, or if source bytes change, archive admission fails, a destination already exists, permissions are not private, or original source record shape is not supported, the product returns HOLD (3), never a cleared or authorized claim.

Private temporary staging builds all outputs before final publication. A partial set of NEW files may remain if a later final publication fails, but no existing user path is overwritten; original case files remain read-only. Original completed source files and SHA indexes are private evidence; protect generated outputs.

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

## Mandatory release gates

**DRAFT/HOLD, do not merge into main or deploy.** Existing exact-head hosted plus permanently named VPS CI, original source-owner acceptance, independent security/privacy, genuinely authenticated separate client and operator permissions with action-time revocation as applicable, and explicit HUMAN GO remain mandatory. The known original scope #301 acceptance failure is not modified or circumvented. No QA suites were created or run.
