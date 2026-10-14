# LightUp scope branch isolation (2026-10-14)

Opt-in **local Git change-set review** for independent scope-authorization workers. This is an advisory, read-only **negative-only** checker, not a trusted security/release attestation, production authorization, human review substitute, or CI policy. LightUp remains **INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD, NO MERGE/NO DEPLOY**.

## Contract

- Caller supplies original **immutable lowercase 40-character** base/head SHAs plus a complete exact manifest of expected newly created files.
- Only additive `tests/test_scope_*.py`, `docs/scope-*.md`, and `scripts/check_scope_*.py` files may pass.
- Maximum 16 changed paths; deny renames, modifications or deletion of existing files, unlisted paths, missing manifest entries, executable bits, symlinks, submodules, and whitespace errors.
- Require both commits to exist and base to be an ancestor of head. Optional repeated `--peer <immutable-peer-sha>` compares the same base against other **locally available, explicitly supplied** worker HEAD commits and denies any overlapping changed path. Git read commands use a bounded timeout and disable external diff/text-conversion filters; Git process errors fail closed. No remote GitHub, DNS, sockets, LightUp imports, executor handlers, target interaction, scanning or state mutation.
- The only successful status is **REVIEW_ONLY**, never *authorized*; `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, and `release_approved` remain strictly `false` even for a syntactically clean change-set.

Example from a **local checkout** with both actual commit SHAs filled in:

```sh
python scripts/check_scope_branch_isolation.py --repo . \
  --base <immutable-base-sha> --head <immutable-head-sha> \
  --allow scripts/check_scope_branch_isolation.py \
  --allow tests/test_scope_branch_isolation.py \
  --allow docs/scope-branch-isolation-review-20261014.md
```

For a known concurrently active branch that has been fetched into the same checkout, append `--peer <exact-other-branch-head-sha>` to check file-path collisions. The receipt records only a count of supplied peers. It **does not discover all branches** or prove unlisted workers have no collisions; the reviewer must inspect GitHub PRs and branches independently. A peer SHA that is missing, invalid, non-descendant, or has an oversized/noncanonical diff fails closed.\n\nTests:

```sh
python -m unittest discover -s tests -p 'test_scope_branch_isolation.py' -v
```

All 15 tests create disposable Git repositories (including simulated missing Git and missing peer commit failures). Passing the checker verifies only local change-path constraints, **not contents, provenance of the supplied manifest, consent, safety of code added in files, exact-head hosted CI, permanent VPS execution, secure source changes, or release approval**. Final path/content review, security/privacy review, registered permanent VPS evidence, and explicit human decision remain independent prerequisites.
