# #905 — strict CLI private-lab marker type (owner-pinned branch-only acceptance)

**Scope posture:** LightUp Incubate M3/M7 PLAN/LAB ONLY. NO MERGE/NO DEPLOY, no target interaction, DNS/network, scans, runtime tool execution, grants or external entities.

## Original owner / collision boundary
Open [#905](https://github.com/Zennay/Lightup/issues/905). The original scope/CLI source owner is [PR #100](https://github.com/Zennay/Lightup/pull/100), and low-level `ScopePolicy` validation is owned by [#165](https://github.com/Zennay/Lightup/pull/165). This **branch-only** isolated acceptance material is pinned directly on exact original #100 commit `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`, **not current main**. That commit's `src/lightup/cli.py::_policy` converts caller-supplied `args.allow_private_lab` via `bool(...)`. Current main has a different `no_private_lab` interface; tests deliberately target the owner lineage, do not falsely claim they cover default main.

## Tests-only material implementation
One new file: `tests/test_scope_905_private_lab_cli_marker_20261012.py`. **13 offline unittest methods**:
- Five deliberate `@expectedFailure` source-owner RED canaries for `"false"`, integer `1`, truthy list, empty string and polymorphic `__bool__` object; all malformed values must ultimately be rejected with controlled `ValueError` **before any ScopePolicy construction/decision**.
- Genuine source positive controls for argparse default exact false, explicit `--allow-private-lab` true, explicit `--no-private-lab` false, mutually-exclusive flag refusal, exact true/false scope decision on a synthetic ordinary private address.
- Input namespace untouched for builtin booleans and explicit characterization of the currently permissive coercion. Even a green source-owner unit test with intentional XFAILs does not prove production is fixed.

Run offline in the exact owner child checkout only:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_905_private_lab_cli_marker_20261012.py' -v
```

## Promotion gate
Source owner #100 must remove the coercion and require `type(args.allow_private_lab) is bool` before policy selection, keep normal argparse semantics, and convert all expected RED cases into ordinary passing deny tests. Validate original #165 lower-level policy contract independently, no public target permissions, and obtain original-source/tenant/security/privacy review, current-main compatibility, exact hosted Python 3.11/3.14 and separately permanent registered VPS CI, explicit human release approval.

This branch is **not a new PR**: the original #100 source owner keeps lane ownership and a pending canonical CI lane must not be multiplied. Only a branch/test/doc handoff is produced; existing PRs/workers/main unchanged. Keep #905 OPEN.


## 2026-10-12 W2 material, independent uninstalled exact-bool implementation

The same **branch-only** original-#100 lineage has been extended with two ADD-ONLY paths:

- `src/lightup/private_lab_cli_guard_optin.py`: uninstalled `checked_private_lab_cli_policy(args)`; requires an *exact* `argparse.Namespace` and an *exact* `bool` marker before delegating to original #100 `_policy`. It does not run CLI commands or authorize targets. It prevents caller-defined `__bool__` execution for malformed marker types.
- `tests/test_scope_905_optin_cli_guard_20261012.py`: 10 green-intent unit methods with exact True/False synthetic private-lab behavior, invalid type pre-delegate `Mock` control, missing key, polymorphic namespace and boolean, parser compatibility, and caller-input immutability.

The original 13 source-owner tests (5 intentional RED) remain untouched. No existing source owner file has changed, no PR/CI has been created, and **no test-success or VPS-run claim is made**. The reference cannot by itself remediate the default CLI policy. `src/lightup/cli.py` remains owned by #100.

Replay on the exact branch checkout only:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_905_*20261012.py' -v
```

Production acceptance still requires #100 owner integration of exact Boolean guard, all original RED→GREEN, privacy/security review, exact hosted 3.11/3.14 CI, registered permanent VPS CI, and explicit release approval; no target authorizations, merge, or deploy.
