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
```

Example contents of `private-lab-targets.txt`:

```text
# Isolated local fixture endpoints
http://127.0.0.1:18080/
http://127.0.0.1:18081/
```

The installed `lightup` entrypoint dispatches the `lab-assess` subcommand through `src/lightup/cli.py` to `labrun.main_assess`. This integration accepts both repeated flags and local manifests. `python -m lightup.labrun` invokes the **different** original single-baseline command and is not this workflow.

## Exactly what is admitted

- CLI arguments and the optional manifest are combined in the order given: positional endpoint, repeated `--target` flags, then file entries. No host/network enumeration, URL fetching, DNS inventory or implicit expansion takes place.
- Up to **16 exact URLs** (at most 2048 characters per entry). The optional user-provided file is read locally with a **16 KiB byte cap** and strict UTF-8, accepting blank and `#` comment lines. Malformed files and duplicates fail before any assessment is initiated.
- Every endpoint passes the existing `LabScenario` / `assert_lab_target` fence **as one batch before model-provider configuration, planning and execution**. Public/non-lab addresses must not be admitted. Execution, if later permitted within the original lab policy, still goes exclusively through the unchanged `ToolExecutor`.
- No-argument invocation retains `http://127.0.0.1:18080/`. An explicitly empty `--targets-file` is rejected rather than secretly using that default.
- `--profile` fixture scoring is restricted to **one** endpoint; multi-endpoint assessments must be unscored rather than being wrongly measured against a one-fixture ground truth.
- Multi-endpoint result JSON reuses existing `targets`, `plan`, `findings`, `coverage`, `evaluation`, and optional `review` fields. Each planner-produced finding already has the concrete `target` identity. This change does not claim completeness, valid security findings or verified remediation.

## Source, ownership and release

Sources: `src/lightup/cli.py` and `src/lightup/labrun.py`, stacked on pre-existing review source [PR #1602](https://github.com/Zennay/Lightup/pull/1602), without changing the review pipeline, original lab target fencing, scope, grants, authentication, workers, state, existing CI or tests. Tracked issue: [#1608](https://github.com/Zennay/Lightup/issues/1608).

This is a **draft implementation**. Original source-owner integration, mandatory exact-head hosted + permanent named VPS CI, independent security/privacy review, appropriate authenticated and separately consented client/operator controls with at-use revocation if any real execution is later contemplated, and explicit HUMAN GO all remain required. Do not merge/deploy/activate while in HOLD.
