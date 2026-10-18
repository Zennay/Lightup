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

## Owner-private completion artifact

Use `--output /private/path/NEW-NAME.json` to keep the original completed assessment JSON, or the optional no-execution input preview, in one **NEW** local private file. The file is created only once with owner-only mode `0600`, never follows the final-component symlink and never silently overwrites an existing file. It may contain targets, findings, evidence references and model-generated text; store it in a trusted private directory, do not commit it to Git and never publicly share it. The command prints only a non-sensitive completion status, not the full report, when writing to a private file. With no `--output`, existing stdout JSON remains unchanged.

Original failed/incomplete model review is **not** written as a completed JSON artifact. The original assessment result remains inspectable using the existing stdout path, with an explicit incomplete-review indication. Neither saved JSON nor its source metadata is an authentication, consent, completed security assessment, audit-trust signature or proof of a fixed vulnerability. Only source-created private file permissions are asserted: already-present destination files and symlinks are refused.

Do not use the output to bypass the mandatory canonical comparator and human review import checks. It is simply the native source for existing offline workflows where the original schema fits.

## Exactly what is admitted

- CLI arguments and the optional manifest are combined in the order given: positional endpoint, repeated `--target` flags, then file entries. No host/network enumeration, URL fetching, DNS inventory or implicit expansion takes place.
- Up to **16 exact URLs** (at most 2048 characters per entry). The optional user-provided file is read locally with a **16 KiB byte cap** and strict UTF-8, accepting blank and `#` comment lines. Malformed files and duplicates fail before any assessment is initiated.
- Every endpoint passes the existing `LabScenario` / `assert_lab_target` fence **as one batch before model-provider configuration, planning and execution**. Public/non-lab addresses must not be admitted. Execution, if later permitted within the original lab policy, still goes exclusively through the unchanged `ToolExecutor`.
- No-argument invocation retains `http://127.0.0.1:18080/`. An explicitly empty `--targets-file` is rejected rather than secretly using that default.
- `--profile` fixture scoring is restricted to **one** endpoint; multi-endpoint assessments must be unscored rather than being wrongly measured against a one-fixture ground truth.
- Multi-endpoint result JSON reuses existing `targets`, `plan`, `findings`, `coverage`, `evaluation`, and optional `review` fields. Each planner-produced finding already has the concrete `target` identity. This change does not claim completeness, valid security findings or verified remediation.

## Multi-endpoint evidence isolation

The original planner-driven lab producer once indexed evidence summaries by `run-id-prefix + check-id`. That identifier is **not unique** when two endpoints emit the same check (e.g. two lab HTTP fixtures both omit the same security header). With a repeatable CLI this becomes a normal use case, and the old map could show endpoint B's summary next to endpoint A's finding.

The producer now retains each summary by its original finding occurrence, next to the original evidence reference. Each finding has a distinct report identity; the first legacy ID remains unchanged, while a collision gets a stable-in-run `~2`, `~3` etc. suffix. Finding order and target, check, severity, remediation and source evidence references remain as before. It does not infer that a security issue is confirmed.

## Source, ownership and release

Sources: `src/lightup/cli.py` and `src/lightup/labrun.py`, stacked on pre-existing review source [PR #1602](https://github.com/Zennay/Lightup/pull/1602), without changing the review pipeline, original lab target fencing, scope, grants, authentication, workers, state, existing CI or tests. Tracked issue: [#1608](https://github.com/Zennay/Lightup/issues/1608).

This is a **draft implementation**. Original source-owner integration, mandatory exact-head hosted + permanent named VPS CI, independent security/privacy review, appropriate authenticated and separately consented client/operator controls with at-use revocation if any real execution is later contemplated, and explicit HUMAN GO all remain required. Do not merge/deploy/activate while in HOLD.
