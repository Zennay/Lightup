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

## Offline start screen and direct navigation

The private ZIP now also contains `index.html`, a responsive, accessible **fully offline launch screen**: direct local links to the ordinal-only printable report, the unmodified original interactive Review Desk, and its manifest. The Review Desk's own browser file picker still requires the reviewer to select `review-desk.json` manually, maintaining the browser's file permission boundary. The start screen forbids network connections, scripts, remote assets and form submission with its own restrictive CSP; the original Review Desk source/CSP remains byte-for-byte unchanged. Both static browser assets are checked by strict SHA-256 before the final ZIP becomes visible; the source manifest records their fingerprints. Opening the start screen or importing data never grants authorization, certifies a benchmark or contacts a target.

## Prioritized human follow-up, without granting authority

Each complete private ZIP now includes `human-worklist.csv`, a bounded **ordinal-only** human planning handoff generated from already-admitted original #1515 metric regression flags. Scope/policy regressions are tagged P1 for human scope-policy review; lab finding/coverage count regressions P2 for the lab-runtime workstream; evidence/rubric regressions P3 for evidence review. These are purely *static suggested human review categories*: they never schedule work, contact targets, assign real people, assert vulnerability severity, grant permissions or override source HOLD. The CSV contains only `Case N`, built-in metric names, static action text and literal `false` authorization/consent/release flags; there are no raw scenario IDs, source paths, assets or original evidence payloads. A non-regressed comparison has the header without invented follow-up items. A HOLD caused by malformed/replayed input creates no package or CSV.

The manifest also includes SHA-256 digests for each newly generated report, Review Desk input JSON and CSV. Together with the pinned browser/app digests, reviewers can detect accidental modifications **after** the package is created; these unsigned digests do not prove source authenticity or release clearance. The private ZIP contains a source-rich JSON file despite privacy-minimal HTML/CSV, so continue protecting the whole ZIP.

## Offline review-package integrity inspector

Recipients can inspect an **already-created** private ZIP with an optional separate, **read-only** command, without opening a browser or trusting input ZIP paths:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_verify_pack_cli_20261018.py \
  /private/EXISTING-review-pack.zip
```

The inspector admits only an explicitly selected bounded **regular, non-symlink local ZIP**, exactly the seven fixed safe member names, strictly bounded decompressed member lengths, no encrypted entries, no unsupported compression, canonical duplicate-free manifest JSON, every required literal-false authority/consent/release flag, the immutable original #1576 browser hash and pinned local start-screen hash, the source fingerprints' canonical shape, original comparator report status consistency and source-member SHA-256 consistency. Bad archives fail with generic `PRIVATE_LAB_PACK_HOLD` and exit **3**, without echoing private contents. Structurally intact packages print only `PRIVATE_LAB_PACK_INTACT — REVIEW_ONLY/HOLD; UNSIGNED; NOT AUTHORIZED` and exit **2**, never 0.

**Important distinction:** this checks packaging/transfer integrity *relative to its own unsigned manifest*, not source authenticity or resistance to a malicious party who replaces both the contents and the manifest. No key, digital signature, original client consent, independent security verdict or release gate is implied or introduced. This is a read-only product tool, not a QA, scanner or CI workaround.

## Privacy-minimal human handoff HTML without source fingerprints

`--format redacted-html --output NEW-brief.html` produces the same printable, ordinal-only metric review **without embedding either original input-source SHA-256 fingerprint**. This is useful when an independent reviewer needs aggregated metric deltas and follow-up notes but must not receive the original source identities or correlatable fingerprints. The original private `html`, `desk-json` and `review-pack` formats are unchanged; all comparisons still use the original #1515 comparator and source admission. The printable output has no original scenario IDs or target IPs but numeric metric combinations can sometimes identify a cohort, so it is **privacy-minimal, not guaranteed anonymous or safe for public release**. No consent, scan or release authority is asserted.

## Compact privacy-minimal review packet for outside human feedback

A separate `--format redacted-pack --output /private/NEW-brief.zip` creates a **different, 4-file** compact review packet with only `READ-ME.txt`, fingerprint-free ordinal `review.html`, `human-worklist.csv`, and a privacy-minimal `manifest.json` recording report/CSV SHA-256, review status, numeric case/regression counts and literal false permission flags. It deliberately excludes: the source-rich `review-desk.json`, original scenario IDs, asset names, original source fingerprints, standalone interactive browser and all raw evidence. All original cases still pass the same local admission and original comparator before any output is created; a canonical regression remains HOLD and a malformed/replayed input yields no artifact. Publication is the same exclusive fsynced private 0600 ZIP, not a public sharing action.

The existing read-only package inspector `assessment_runtime_verify_pack_cli_20261018.py` now also recognizes the **exact separate 4-file** `lightup.ordinal_review_brief.v1` schema, bounding every decompressed member, preserving false permission flags and checking the brief's own unsigned manifest/member digests. It still recognizes the original full private seven-file package. Since even numeric aggregate metric combinations can be sensitive, **redacted means minimized, not anonymous or approved for publication**. No real benchmark truth, security assurance, authenticated consent, human GO or deployment permission is asserted.

## Restore original human Review Desk planning into a complete private archive

The independent unchanged browser Review Desk #1576 can export human stages, workstreams and follow-up dates as `lightup-offline-human-triage-v1/v2` JSON. The new CLI turns a validated original seven-file private ZIP and **that exact source-bound browser export** into a complete new ten-file private archive:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_attach_triage_cli_20261018.py \
  /private/ORIGINAL-review.zip /private/BROWSER-saved-review.json \
  --output /private/NEW-followup-review.zip
```

Original `review-desk.json` bytes must SHA-256 match the browser review `source_sha256`; accepted cases must match original ordered ordinal labels, statuses, source-regression names and derived priorities. The v1/v2 import strictly accepts original human stage, optional calendar due date and selected workstream; no extra fields/identity/permission claims. On mismatch generic HOLD and no new output. Source comparison data, authority flags and original browser app remain unmodified.

The ten-file source-bound packet preserves seven original members except the versioned v2 manifest, and adds `saved-human-review.json` plus `human-summary.html` (print-ready human follow-up without original case identities). In the original browser open `review-desk.json`, then **Restore saved review** by selecting `saved-human-review.json`; its original SHA gate is preserved. The read-only package inspector now admits the exact v1 (7-file) and v2 (10-file) manifests and verifies the saved review against its original comparison source, plus all member hashes. The ZIP remains private 0600 with atomic publication and cannot approve scanning, consent, dispatch, release or waive HUMAN GO.

### Single-snapshot source handling for a saved review

The source-bound human follow-up command opens and reads its explicitly selected original private ZIP **only once**. It hands that same bounded raw byte snapshot directly to the offline inspector, then reuses exactly those bytes to copy the original members. This prevents a user-controlled file path from being replaced between inspection and packaging. The original read-only inspector retains its ordinary path-based CLI, while exposing `inspect_bytes` for already-opened private snapshots; no additional release or QA gate is introduced.

## Separate minimized recipient handoff AFTER human review

After the browser's source-bound saved review has been attached to an original seven-file package, the resulting valid **ten-file private ZIP** can be turned into a small **four-file human-only handoff** without disclosing the original scenario IDs or source SHA fingerprints:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_human_handoff_cli_20261018.py \
  /private/ORIGINAL-annotated-ten-file-review.zip \
  --output /private/NEW-private-recipient-handoff.zip
```

The source annotated packet is snapshotted once, inspected using its original source/manifest/plan binding, and never revisited. The output contains only `human-summary.html` (ordinal case labels, human stages, route, due date and metric names), `human-worklist.csv` (original suggested human-only regression follow-up), `READ-ME.txt` and `manifest.json` (source status, aggregate stage counts and unsigned recipient-member SHA-256 hashes, all authorization/consent/dispatch/release flags false). It has **no** original scenario IDs, URLs, clients, source record JSON, source byte fingerprints, private interactive desk, grants or imported raw human planning JSON. Numeric metric combinations or dates could nevertheless be identifying: this is minimized private disclosure, NOT anonymous public data. A recipient cannot use this smaller packet to impersonate a source report or restore an authorization.

The same read-only `assessment_runtime_verify_pack_cli_20261018.py` product inspector now admits this exact fourth fixed layout and checks aggregated stage-count coherence, hashes and all no-authority flags. The original full private and redacted metric packets remain unaffected. Source HOLD stays HOLD, and publication uses the original atomic `0600` new-only output primitive.


### Direct offline entry screen for saved human reviews

A complete source-bound **ten-member** follow-up ZIP includes `review-followup.html`, a separately hash-pinned responsive browser launcher. Open it after extracting the trusted private archive: it links to `human-summary.html` and provides the exact two-step original desk workflow (select `review-desk.json`, then restore `saved-human-review.json`). It also links to the unchanged metric source printout. The screen has no scripts or network access and never changes case status or grants approval. The original pinned Review Desk and older seven-file package remain byte-for-byte unchanged. The same archive inspector admits exactly the ten fixed v2 members and their expected manifest hashes.


## Offline HUMAN capacity planning across completed review packets

Use the capacity companion only after separate original review packets have already been created and locally reviewed. It aggregates the existing HUMAN follow-up rows across 2–8 distinct annotated private review ZIPs; it does not reopen targets or execute assessments.

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_cli_20261023.py \
  /private/REVIEW-01.zip /private/REVIEW-02.zip \
  --capacity-per-group 4 --reference-date 2026-10-23 \
  --output /private/NEW-human-capacity.zip

PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_inspect_cli_20261023.py \
  /private/NEW-human-capacity.zip
```

The capacity bundle is a fixed six-member PRIVATE ZIP: scriptless local HTML summary, detailed `capacity.csv`, aggregate `capacity-summary.csv` (priority/stage/route counts, date/route load and priority/date/route open-work counts), canonical JSON work rows, schema-v2 manifest with unsigned output digests, and a privacy/no-authority guide. The optional capacity value is only a hypothetical number of HUMAN rows per route/date; the explicit reference date is required for overdue counts. Use `--preview-only` without `--output` to print aggregate counts without publishing files.

Only distinct original comparison bytes are counted once; changing HUMAN notes on the same comparison does not make a new independent case. `reviewed` rows are excluded from open planning load but remain HUMAN self-reports, not verified fixes or approvals. All outputs remain private and potentially sensitive. Digests are unsigned integrity checks, not authentication. This feature does not grant authorization, prove consent, dispatch handlers, verify remediation, or permit release.

Full operator instructions: [assessment_runtime_human_capacity_README_20261023.md](assessment_runtime_human_capacity_README_20261023.md).
