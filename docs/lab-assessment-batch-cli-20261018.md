# Isolated multi-endpoint lab assessment CLI

**Stage:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This change is an input affordance for existing lab-only assessment infrastructure, **not** public-scope consent, a scanner release, an execution grant, a security certification or permission to target third-party systems.

## Usage

Existing single-endpoint and zero-argument forms remain available:

```sh
lightup lab-assess
lightup lab-assess http://127.0.0.1:18080/
```

New multi-endpoint forms (only isolated labs you own/control):

```sh
lightup lab-assess --target http://127.0.0.1:18080/ --target http://127.0.0.1:18081/
lightup lab-assess http://127.0.0.1:18080/ --target http://127.0.0.1:18081/
lightup lab-assess --targets-file ./private-lab-targets.txt --no-review
lightup lab-assess --targets-file ./private-lab-targets.txt --preview-only
lightup lab-assess --targets-file ./private-lab-targets.txt --preview-only --output ./private-lab-preview.json
lightup lab-assess --targets-file ./private-lab-targets.txt --no-review --output ./private-lab-assessment.json
lightup lab-assess --target http://127.0.0.1:18080/ --no-review --artifact-format benchmark-case --output ./private-lab-benchmark-case.json
```

Example contents of `private-lab-targets.txt`:

```text
# Isolated local fixture endpoints
http://127.0.0.1:18080/
http://127.0.0.1:18081/
```

The installed `lightup` entrypoint dispatches the `lab-assess` subcommand through `src/lightup/cli.py` to `labrun.main_assess`. This integration accepts both repeated flags and local manifests. `python -m lightup.labrun` invokes the **different** original single-baseline command and is not this workflow.

## No-execution input preview

Use `--preview-only` with either `--target` or `--targets-file` to check the same complete batch of lab inputs without starting the model gateway, planner or any network worker. The JSON preview contains `mode: "LAB_INPUT_PREVIEW_ONLY"`, the normalized lab-host candidates, endpoint count, and explicit `false` execution/authorization fields. The preview **does not echo the original URLs**: query strings and embedded userinfo may be sensitive. It does not authenticate an owner, issue an approval, prove engagement rights, assert vulnerability findings, create a plan, grant consent or interact with any target.

`--preview-only` is a user-facing offline preparation step, **not** a replacement for any mandatory release/CI/security gate. Passing this preview never authorizes a later assessment.

## Connect the original offline Lab Scenario Studio

The existing offline Studio ([draft PR #1595](https://github.com/Zennay/Lightup/pull/1595)) exports a PRIVATE `lightup.lab_design_catalog.v1` JSON catalog of human-authored numeric lab IPs. It contains **design**, not executable URL/port mappings, authenticated authorization or trusted benchmark truth. The installed CLI can now deliberately select one of those drafts and bind every declared numeric target to one **separately entered explicit HTTP(S) URL and port**:

```sh
lightup lab-assess \
  --catalog-file ./PRIVATE-scenario-studio.json \
  --scenario-id fixture-exposed \
  --target http://127.0.0.1:18080/ \
  --preview-only

lightup lab-assess \
  --catalog-file ./PRIVATE-scenario-studio.json \
  --scenario-id fixture-exposed \
  --target http://127.0.0.1:18080/ \
  --no-review --output ./private-lab-source.json
```

All original Studio v1 catalog records must pass exact source schema, duplicate-key, UTF-8, size (256 KiB), private numeric target, unique scenario/check identity and literal-false authority checks before the selected record is exposed. The selected scenario's ID/name/description are passed to the existing `LabScenario` dataclass. **Every declared address must have exactly one independently entered matching numeric HTTP(S) URL with an explicit port.** Hostnames, credentials, extra/missing assets, ambiguous source aliases and mismatched addresses are rejected before creating a plan or invoking a model or worker. The original lab scope fence is applied again.

A Studio-authored catalog's `expected_findings` values are **never** automatically treated as trusted benchmark ground truth. The runtime uses `expected_findings=None` (unscored) and does not allow mixing with installed `--profile` ground truth. Its result carries only an **unsigned** SHA-256 source fingerprint, selected scenario ID, declared finding count and literal-false authenticated/scored/authority flags. A hash is not a signature or proof of ownership, consent, a real test result, or a vulnerability. Catalog paths and private descriptions are not echoed in public output.

This interface is a source-isolated integration on top of Studio's published schema; it does **not** edit Studio's original `lab-design/` files or active branch. The run path is still subject to the exact original ScopePolicy, ToolExecutor and release constraints.

## Owner-private completion artifact

Use `--output /private/path/NEW-NAME.json` to keep the original completed assessment JSON, or the optional no-execution input preview, in one **NEW** local private file. The destination path and parent directory are checked before starting an assessment so obvious unavailable paths are rejected before model/tool interaction. Complete JSON is first written and fsynced to a temporary owner-only `0600` file in the same directory; only afterwards is the final destination name atomically introduced via an **exclusive filesystem hard-link** (not an overwriting rename). A concurrent final file or symlink is rejected rather than replaced. If writing fails, no incomplete destination is published, and ordinary failures clean up the private temporary file. A sudden process or host failure can leave an owner-only staging file requiring manual cleanup, but not a partially written final artifact. It may contain targets, findings, evidence references and model-generated text; store it in a trusted private directory, do not commit it to Git and never publicly share it. The command prints only a non-sensitive completion status, not the full report, when writing to a private file. With no `--output`, existing stdout JSON remains unchanged.

Original failed/incomplete model review is **not** written as a completed JSON artifact. The original assessment result remains inspectable using the existing stdout path, with an explicit incomplete-review indication. Neither saved JSON nor its source metadata is an authentication, consent, completed security assessment, audit-trust signature or proof of a fixed vulnerability. Only source-created private file permissions are asserted: already-present destination files and symlinks are refused.

Do not use the output to bypass the mandatory canonical comparator and human review import checks. It is simply the native source for existing offline workflows where the original schema fits.

## Original offline benchmark-comparator handoff

The separate existing assessment-runtime comparator [PR #1515](https://github.com/Zennay/Lightup/pull/1515) expects one `{"record": {...}, "context": {...}}` JSON object per finished lab run. For a lab fixture that is independently owned/controlled and available through the **unchanged** lab-only execution policy, request `--artifact-format benchmark-case --output ./NEW-private-benchmark.json`. This format is **not** available with `--preview-only` because a preview has no actual evaluation record. A private output filename is mandatory, so source-rich run context is never accidentally printed as standard output in this mode.

When the original evaluation successfully completes, the existing `LabEvaluationHarness`'s actual `EvaluationRecord.to_dict()` and **the exact original `RunContext`** (run ID, lab client+engagement, mode, risk, NULL grant, is_lab and UTC creation timestamp) are serialized without changes to the comparator source or schema. The saved JSON has exactly the comparator's two top-level `record` and `context` fields, and inherits the same new exclusive owner-only `0600` private write fence. The optional AI review is still independent; a failed selected review does not export an apparent completed artifact. The original comparator **must still independently reject replayed or inconsistent run IDs, malformed record/context shapes and adverse metrics**, and its REVIEW_ONLY/HOLD statuses confer no execution or release permission.

**Do not infer provenance:** even a correctly-shaped `record/context` file is only an unsigned, caller-controlled local export. It does not prove lab fixture authenticity, authorize any target, certify ground truth or replace authentic client/operator approval, at-use revocation, security review, permanently registered CI, or HUMAN GO. The public default assessment output shape is unchanged; the new field is built only for this explicit private export.

## Exactly what is admitted

- CLI arguments and the optional manifest are combined in the order given: positional endpoint, repeated `--target` flags, then file entries. No host/network enumeration, URL fetching, DNS inventory or implicit expansion takes place.
- Up to **16 exact URLs** (at most 2048 characters per entry). The optional user-provided file is read locally with a **16 KiB byte cap** and strict UTF-8, accepting blank and `#` comment lines. Malformed files and duplicates fail before any assessment is initiated.
- Every endpoint passes the existing `LabScenario` / `assert_lab_target` fence **as one batch before model-provider configuration, planning and execution**. Public/non-lab addresses must not be admitted. Execution, if later permitted within the original lab policy, still goes exclusively through the unchanged `ToolExecutor`.
- No-argument invocation retains `http://127.0.0.1:18080/`. An explicitly empty `--targets-file` is rejected rather than secretly using that default.
- `--profile` fixture scoring is restricted to **one** endpoint; multi-endpoint assessments must be unscored rather than being wrongly measured against a one-fixture ground truth.
- Multi-endpoint result JSON reuses existing `targets`, `plan`, `findings`, `coverage`, `evaluation`, and optional `review` fields. Each planner-produced finding already has the concrete `target` identity. This change does not claim completeness, valid security findings or verified remediation.

## Inspect saved PRIVATE results without exposing details

After an operator has an explicitly chosen local result file, `lightup lab-inspect /private/path/report.json` reads **only that existing local regular JSON file**. It uses bounded, no-follow, no-network input, rejects duplicate JSON keys and nonfinite values, and prints a privacy-minimal summary without original host IPs, scenario or finding names, evidence, full model output, client information, passwords or original file paths. Supported inputs are the CLI's preview JSON, completed original full-assessment JSON, and the two-field `benchmark-case` JSON artifact.

The output includes *declared* endpoint/finding counts, severity breakdown, evidence-reference availability, source finding-ID continuity and whether an optional model review is present. Benchmark packets show only explicitly declared aggregate metrics. Invalid, ambiguous or unsupported files produce generic `HOLD` without source data. **Exit status 2 is REVIEW_ONLY; status 3 is HOLD. Success exit 0 is deliberately impossible for the inspector**, and REVIEW_ONLY does not mean a source was authentic, a target was authorized, metrics are reliable, a vulnerability is confirmed, or anything can be released.

```sh
lightup lab-assess --targets-file ./lab-targets.txt --preview-only --output ./new-private-preview.json
lightup lab-inspect ./new-private-preview.json
```

A separately authored Studio design is still untrusted until admitted through the original native LabScenario boundary. No benchmark comparison, model, lab work, scan or approval is initiated by this inspector.

## Safe lab URL and manifest admission

Before any model gateway, planner or target tool, the installed lab CLI admits only bounded printable HTTP(S) URLs with host identities, syntactically valid ports, and **no embedded username/password or URL fragments**. Every endpoint still passes the independent original lab scope fence. No DNS lookup, enumeration or external URL fetching is introduced. A local `--targets-file` must be an actual bounded regular file (not a symbolic link, FIFO, character device or directory); it is read without following the final pathname symlink. Invalid or rejected inputs, private catalog data and provider failures produce **generic CLI errors** rather than echoing source URLs, filenames or provider exception text. A model-review failure is explicitly marked incomplete rather than appearing as verified evidence.

## Stable finding correlation through review and report

The original report Markdown had a source finding identity, but the planner-driven JSON result had omitted `finding_id`, leaving operators unable to reliably match similarly titled checks across endpoints. JSON findings now carry the original unique `finding_id` next to target, evidence references and evidence summary; the assessment-review pipeline preserves it in reviewed findings and the report synthesizer's per-finding inputs. Repeated IDs are rejected across the entire review batch before the first verifier/model request. For older standalone review dictionaries with no finding ID, the original output shape remains supported; no identity is invented. IDs identify local records, **not** authenticated provenance, unique vulnerability truth, or consent.

## Multi-endpoint evidence isolation

The original planner-driven lab producer once indexed evidence summaries by `run-id-prefix + check-id`. That identifier is **not unique** when two endpoints emit the same check (e.g. two lab HTTP fixtures both omit the same security header). With a repeatable CLI this becomes a normal use case, and the old map could show endpoint B's summary next to endpoint A's finding.

The producer now retains each summary by its original finding occurrence, next to the original evidence reference. Each finding has a distinct report identity; the first legacy ID remains unchanged, while a collision gets a stable-in-run `~2`, `~3` etc. suffix. Finding order and target, check, severity, remediation and source evidence references remain as before. It does not infer that a security issue is confirmed.

## Source, ownership and release

Sources: `src/lightup/cli.py`, `src/lightup/labrun.py` and the newly added strict `src/lightup/lab_catalog.py`, stacked on pre-existing review source [PR #1602](https://github.com/Zennay/Lightup/pull/1602), without changing the review pipeline, original lab target fencing, scope, grants, authentication, workers, state, existing CI or tests. Tracked issue: [#1608](https://github.com/Zennay/Lightup/issues/1608).

This is a **draft implementation**. Original source-owner integration, mandatory exact-head hosted + permanent named VPS CI, independent security/privacy review, appropriate authenticated and separately consented client/operator controls with at-use revocation if any real execution is later contemplated, and explicit HUMAN GO all remain required. Do not merge/deploy/activate while in HOLD.
