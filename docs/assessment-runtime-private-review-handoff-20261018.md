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

For original #1515 **cohort** format (each file an array of 1–64 two-field cases), add `--cohort`. This does not import Lab Scenario Studio ground-truth into comparative scores or claim those self-declared expectations as verified. An existing private report path or symlink is refused, never overwritten. Both bundle and report are completely written and fsynced into a private same-directory temporary file before the final destination becomes visible via a no-overwrite hard link; a failed/incomplete export never publishes a partial final file.

A valid comparison creates a bounded **owner-only 0600, single-file printable HTML** review with per-metric deltas, scenario-specific regressions for cohorts, original input-byte SHA-256 digests, and an explicit pending human handoff. No JavaScript, remote assets, HTTP calls, source filesystem paths, raw evidence, or credential payloads are embedded. SHA-256 is **not** signature/attestation/provenance. Retain the source files privately; the output itself is confidential. Invalid/replayed HOLD input creates no document. A canonical comparison with actual metric regressions still creates a clearly HOLD-marked private review document and exits 3, so a human can inspect the regression without any execution/release authority.

A non-regressed comparison prints `PRIVATE_LAB_REVIEW_WRITTEN — REVIEW_ONLY; NOT AUTHORIZED` and exits **2** (intentionally never 0). Malformed, forged, replayed, non-lab, incompatible, duplicate-key, non-finite, non-regular/symlinked or unbounded input produces only the generic `LAB_REVIEW_HOLD` marker and exit **3**, without echoing source data. Original #1515's validated comparison rules remain the only metric authority; this script is a passive renderer, not a scoring or approval replacement.

## Release boundary

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Neither this document nor the source JSON establishes real client consent, operator approval, current revocation checks, actual scanner outcome, independent security/privacy clearance, required hosted/permanent registered VPS CI, or human release authorization. Never merge to main, deploy, grant, execute active handlers or contact targets based on REVIEW_ONLY. No QA/test files, workflow, permission, runtime handler or other worker branch are changed here.

## Build an original comparator cohort without hand-editing JSON

A second **independent local product step** is `scripts/assessment_runtime_case_bundle_cli_20261018.py`: package 1–64 **already-completed** original individual benchmark-case JSON files into one bounded cohort array accepted unchanged by #1515. It parses each source with the original parser, applies original lab-only record/context/scenario and duplicate admission, rejects oversized cohorts, and writes only a new private 0600 JSON file (never overwriting). It does **not** synthesize findings, ground truth, consent or new runs.

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_case_bundle_cli_20261018.py \
  /private/baseline-a.json /private/baseline-b.json \
  --output /private/NEW-baseline-cohort.json
PYTHONPATH=src:scripts python scripts/assessment_runtime_case_bundle_cli_20261018.py \
  /private/candidate-a.json /private/candidate-b.json \
  --output /private/NEW-candidate-cohort.json
PYTHONPATH=src:scripts python scripts/assessment_runtime_review_handoff_cli_20261018.py \
  /private/NEW-baseline-cohort.json /private/NEW-candidate-cohort.json \
  --cohort --output /private/NEW-comparison-review.html
```

The two cohort inputs must contain matching scenario identities; source run and record IDs must not be replayed between baseline/candidate. Bundling itself cannot verify that a source case was genuinely collected; fingerprints and records are still caller-supplied. Bundle success prints `PRIVATE_LAB_COHORT_WRITTEN — UNVERIFIED; NOT AUTHORIZED` and exits 2; any rejected input prints only `LAB_COHORT_HOLD` and exits 3. Neither exit grants any permission.

## Direct integration with the original interactive human Review Desk (#1576)

The previously independent printable-review CLI can also save the original **#1515 comparator's exact JSON result schema** directly to a new private file, without copying or reimplementing its scoring rules. This connects current original benchmark cases with the existing [offline Review Desk #1576](https://github.com/Zennay/Lightup/pull/1576) without editing that owner's source:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_review_handoff_cli_20261018.py \
  /private/NEW-baseline-cohort.json /private/NEW-candidate-cohort.json \
  --cohort --format desk-json --output /private/NEW-reviewdesk-input.json
```

Download/open the original [Review Desk standalone HTML](https://github.com/Zennay/Lightup/blob/chatgpt/lightup-assessment-reviewdesk-20261018/assessment-review/standalone.html) **locally**, then use its file import to read the saved JSON. It recognizes the original single-case or cohort comparison data shape. The CLI reuses the original #1515 `_display`/`_output` serializers, not a locally invented contract. No network, website, backend or grant is involved; the browser consumes a user-selected file. **The intermediary JSON is source-rich and may contain raw scenario IDs and metric values; unlike the privacy-minimal desk's downstream exports, this JSON must remain private.** Use the separate HTML format when the human recipient must not see source scenario IDs.

Regressions remain `HOLD`, with explicit false permission flags. Unlike an invalid or replayed record, a canonical regression produces a real JSON result so the browser can triage it. This import is evidence for *human preparation only*, never permission to scan, grant, deploy or merge.

## Direct multi-scenario review without intermediate JSON bundle files

For operators who already have a fixed, independently completed set of 1–64 original benchmark cases from baseline and candidate runs, the same review CLI now accepts **explicit repeated original case filenames**. It reuses the unchanged #1515 source parser/record admission and atomic comparator. There is no filesystem globbing, folder scan, wildcard, generated benchmark or implicit target interaction. The two sets must contain precisely the same original scenario IDs, no replayed record/run identities, and fit the original bounded cohort representation.

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_review_handoff_cli_20261018.py \
  --baseline-case /private/baseline-a.json \
  --baseline-case /private/baseline-b.json \
  --candidate-case /private/candidate-a.json \
  --candidate-case /private/candidate-b.json \
  --format desk-json --output /private/NEW-reviewdesk-input.json
```

Omit `--format desk-json` to get the print-ready private HTML instead. Explicit per-case inputs cannot be combined with positional cohort inputs or `--cohort`; unsupported combinations fail with the generic HOLD. For direct case lists, the report's SHA-256 identifiers cover the assembled **canonical cohort JSON bytes**, not the original individual on-disk file bytes and are never described as signed provenance. To retain a standalone cohort file for another original consumer, use the separate atomic case bundle command documented above.

## Single private review packet for real human handoff

To avoid generating and transferring two different review files, the same CLI now accepts **`--format review-pack`** and atomically writes **one** new owner-only `0600` ZIP, using the existing private fsync + exclusive hard-link publication. Example with two already-existing canonical cohort files:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_review_handoff_cli_20261018.py \
  /private/baseline-cohort.json /private/candidate-cohort.json \
  --cohort --format review-pack --output /private/NEW-review-pack.zip
```

The fixed archive contains exactly `review.html` (printable local summary with **ordinal case labels, never original scenario IDs**), `review-desk.json` (the original #1515 comparison result for import into the existing #1576 browser desk) and `manifest.json` (comparison type, source-byte/canonical-cohort fingerprints, status and permanently false authorization/consent/dispatch/release fields). The archive is created wholly in memory and published as one complete new file. It does not include input case files, target URLs, raw evidence bytes, provider logs, scripts, executable HTML JavaScript, network assets or new ground-truth assertions.

**Privacy:** `review-desk.json` necessarily retains the *original* scenario IDs because the original Review Desk uses them for identity matching. The entire ZIP is therefore confidential and should be kept inside a trusted private directory; share only `review.html` when a recipient must see ordinal-only case labels. Source hashes are unsigned byte fingerprints, not trust attestation. Input cases still must be independently authenticated before any real authorization, security outcome or deployment decision. A canonical regression produces a private packet marked HOLD and exit 3; invalid/replayed source inputs produce only generic HOLD and no packet.

## Original run/record identity continuity across the whole review

The bundle command and cohort review now refuse a copied original `run_id` or `record_id` anywhere **within either cohort or across both baseline and candidate cohorts**, even if the duplicate occurs under a different scenario name. A normal original `LabEvaluationHarness` creates independent record/run identities for separate lab cases. The original #1515 comparator also rejects same-scenario replay; this extra review-entry guard prevents a source record from being laundered into a *different* scenario within a single human packet. A collision produces the same generic HOLD and publishes no output. This is syntactic source identity hygiene only, **not** proof of authentic provenance, client approval or a security outcome; no original #1515 owner source was changed.

## Complete original offline Review Desk included in the ZIP

`--format review-pack` now ships the **unchanged byte-exact original** standalone HTML from independent Review Desk [PR #1576](https://github.com/Zennay/Lightup/pull/1576), source commit `bb5c2299d3697781db7093aaea79ed418f1cc07c`, archived asset SHA-256 `3f578faae06b40dea47cfac8e8318fa8db5dd117b5f3f7e0d5a7853e426fbe29`. The tool reads the pinned `assessment-review-pack/review-desk.html` from its own source tree, requires an exact regular-file SHA-256 match before releasing any ZIP, and **never fetches or alters another owner's live branch**.

The complete ZIP contains exactly `START-HERE.txt`, `review.html`, `review-desk.html`, `review-desk.json` and `manifest.json`. Extract privately, open `review-desk.html` in a browser without a server and select `review-desk.json` in its existing local file picker. The original browser UI remains self-contained with its original hashed CSP and never receives automatic file access. The manifest includes the exact original Review Desk source commit and SHA-256. Treat the ZIP as source-sensitive; it includes unredacted scenario identity in the comparison JSON. This is offline **human review only**, not a release/scan or consent workflow.
