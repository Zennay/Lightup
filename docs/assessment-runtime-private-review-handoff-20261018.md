# Private, printable lab review handoff (assessment-runtime #1513)

New standalone entry point: `scripts/assessment_runtime_review_handoff_cli_20261018.py`. Stacked on the existing **draft** offline comparator source [PR #1515](https://github.com/Zennay/Lightup/pull/1515). It does not modify either #1515 owner's parser or active assessment-runner [PR #1610](https://github.com/Zennay/Lightup/pull/1610).

## Operator workflow

Start with **two independently completed, private LAB-only benchmark-case JSON exports** of the original two-field `{"record":...,"context":...}` structure. These can be exported by the separately held draft #1610 `lightup lab-assess --no-review --artifact-format benchmark-case --output NEW.json`, only after its *existing* real lab gates; do **not** execute new assessments merely to generate a demonstration.

From this repository checkout:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_review_handoff_cli_20261018.py \
  /private/lab-baseline.json /private/lab-candidate.json \
  --output /private/NEW-lab-review.html
```

For original #1515 **cohort** format (each file an array of 1–64 two-field cases), add `--cohort`. This does not import Lab Scenario Studio ground-truth into comparative scores or claim those self-declared expectations as verified. An existing private report path or symlink is refused, never overwritten.

A valid comparison creates a bounded **owner-only 0600, single-file printable HTML** review with per-metric deltas, scenario-specific regressions for cohorts, original input-byte SHA-256 digests, and an explicit pending human handoff. No JavaScript, remote assets, HTTP calls, source filesystem paths, raw evidence, or credential payloads are embedded. SHA-256 is **not** signature/attestation/provenance. Retain the source files privately; the output itself is confidential. No files are created for HOLD input.

An admitted comparison prints `PRIVATE_LAB_REVIEW_WRITTEN — REVIEW_ONLY; NOT AUTHORIZED` and exits **2** (intentionally never 0). Malformed, forged, replayed, non-lab, incompatible, duplicate-key, non-finite, non-regular/symlinked or unbounded input produces only the generic `LAB_REVIEW_HOLD` marker and exit **3**, without echoing source data. Original #1515's validated comparison rules remain the only metric authority; this script is a passive renderer, not a scoring or approval replacement.

## Release boundary

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Neither this document nor the source JSON establishes real client consent, operator approval, current revocation checks, actual scanner outcome, independent security/privacy clearance, required hosted/permanent registered VPS CI, or human release authorization. Never merge to main, deploy, grant, execute active handlers or contact targets based on REVIEW_ONLY. No QA/test files, workflow, permission, runtime handler or other worker branch are changed here.
