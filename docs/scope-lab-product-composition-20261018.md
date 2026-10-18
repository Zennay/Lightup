# LightUp scope + lab product composition — DRAFT/HOLD

This standalone review branch unifies unmodified source contributions without changing either owner branch or the production main branch.

## Pinned source provenance

- Scope-policy/source integration: [PR #1616](https://github.com/Zennay/Lightup/pull/1616) pinned base `33d5e070f29f76521c3df8963d6aed6a801cb793`.
- Lab operator source: [PR #1610](https://github.com/Zennay/Lightup/pull/1610) pinned head `74e865201c8a4270e404046ef3447eb7f190edfb`.
- Directly carried over: `labrun.py`, `lab_catalog.py`, `lab_inspect.py`, `ai/pipeline.py` and related owner documentation. CLI command parser and lab dispatch copied from #1610 *inside* #1616's policy-secure CLI; all #1616 scope-policy and error fences retained. No test, workflow or original source-owner files were edited on the original branches.

## Operator-visible product

`lightup lab-assess` can preview 1–16 isolated lab endpoints, accept explicit local target manifests and Studio scenario catalogs, prepare private 0600 JSON exports, and produce native offline benchmark-case envelopes. Repeated check IDs on distinct endpoints retain their corresponding evidence. `lightup lab-inspect` supplies an offline aggregate-only inspection command. All non-authority review flags remain false.

### No-execution command preview

```sh
PYTHONPATH=src python3 -B -m lightup.cli lab-assess --target http://127.0.0.1:18080/ --preview-only
PYTHONPATH=src python3 -B -m lightup.cli lab-inspect --help
PYTHONPATH=src python3 -B -m lightup.cli scope-check example.com
```

The last command deliberately returns exit 2/out-of-scope; this is not a target probe. Live code syntax parsed and the preview executed on zSSH; no QA/regression/test suites written or run. Preview performs no plan/model/network/target actions.

## Mandatory release HOLD

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No main merge, deploy, real target interaction, scanner, grants, handler dispatch or execution authority. Still requires original source-owner/security/privacy review, actual separately authenticated client/operator consent with at-use revocation, complete exact-head hosted + permanent registered VPS CI, and explicit HUMAN GO. No output from this offline workflow substitutes for these controls. Owner branch changes require renewed integration review.
