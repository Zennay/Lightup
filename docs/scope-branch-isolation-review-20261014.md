# LightUp scope branch isolation (2026-10-14)

Opt-in **local Git change-set review** for independent scope-authorization workers. This is an advisory, read-only **negative-only** checker, not a trusted security/release attestation, production authorization, human review substitute, or CI policy. LightUp remains **INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD, NO MERGE/NO DEPLOY**.

## Contract

- Caller supplies original **immutable lowercase 40-character** base/head SHAs plus a complete exact manifest of expected newly created files.
- Only additive `tests/test_scope_*.py`, `docs/scope-*.md`, and `scripts/check_scope_*.py` files may pass.
- Maximum 16 changed paths and at most 256 KiB per added blob; deny renames, modifications or deletion of existing files, unlisted paths, missing manifest entries, executable bits, symlinks, submodules, non-UTF-8/NUL files, BOM, terminal/control characters, invisible Unicode format code points (including bidi overrides and zero-width selectors), and whitespace errors. Byte-level text validation does not evaluate source semantics or establish that new Python files are safe to execute.
- Require both commits to exist and base to be an ancestor of head. Optional repeated `--peer <immutable-peer-sha>` compares the same base against other **locally available, explicitly supplied** worker HEAD commits and denies overlapping changed paths, including case-folded aliases that would collide on case-insensitive checkouts. Git read commands use a bounded timeout, disable external diff/text-conversion filters, clear inherited `GIT_*` overrides and system/global Git config, and pin the actual checkout root. The reviewer overrides Git whitespace configuration to keep trailing-whitespace detection enabled; Git process errors fail closed. No remote GitHub, DNS, sockets, LightUp imports, executor handlers, target interaction, scanning or state mutation.
- The only successful status is **REVIEW_ONLY**, never *authorized*; `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, and `release_approved` remain strictly `false` even for a syntactically clean change-set.

Example from a **local checkout** with both actual commit SHAs filled in:

```sh
python scripts/check_scope_branch_isolation.py --repo . \
  --base <immutable-base-sha> --head <immutable-head-sha> \
  --require-current-head \
  --allow scripts/check_scope_branch_isolation.py \
  --allow tests/test_scope_branch_isolation.py \
  --allow docs/scope-branch-isolation-review-20261014.md
```

For a known concurrently active branch that has been fetched into the same checkout, append `--peer <exact-other-branch-head-sha>` to check file-path collisions. The receipt separates `peer_heads_submitted` from `peer_heads_checked`; a HOLD never claims peer checks were completed. It **does not discover all branches** or prove unlisted workers have no collisions; the reviewer must inspect GitHub PRs and branches independently. A peer SHA that is missing, invalid, non-descendant, or has an oversized/noncanonical diff fails closed.

Tests:

```sh
python -m unittest discover -s tests -p 'test_scope_branch_isolation.py' -v
```

All 28 test methods use disposable Git repositories or isolated fake Git subprocess failures, including oversize text, invalid UTF-8 and NUL-bearing Git blobs. They cover inherited Git env redirection, nested-checkout paths, overridden whitespace policy, honest HOLD receipts, and timeout behavior. Passing the checker verifies only local change-path constraints, **not contents, provenance of the supplied manifest, consent, safety of code added in files, exact-head hosted CI, permanent VPS execution, secure source changes, or release approval**. Final path/content review, security/privacy review, registered permanent VPS evidence, and explicit human decision remain independent prerequisites.

This opt-in reviewer accepts ordinary printable multilingual UTF-8. It intentionally rejects Unicode general-category `Cf` (invisible formatting) and `Cc` except newline and tab, plus leading BOM, to reduce reviewer display ambiguity. This is a conservative offline admission policy, **not** a statement that rejected text is intrinsically malicious or that accepted text is safe to run.

For review of a checked-out worker branch, use `--require-current-head` as shown above: it refuses an immutable head SHA that is not the checkout's current `HEAD`. Omitting the flag intentionally allows reviewing *historical* detached snapshots; such a review does not establish freshness and must never be described as a live branch audit.
