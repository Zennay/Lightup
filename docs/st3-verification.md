# ST3 subject resolution verification

The subject resolver is staged in PR #27. It accepts an explicit evidence-backed
decision only for an existing single-candidate CHANGE binding. Its output is a
verified subject association, not a verified attack path or production verdict.

## What is exercised

- Standalone regression suite, including tenant isolation, ambiguous/missing
  candidates, evidence identity, canonical projected state, stale decisions,
  collision rejection and exact replay.
- The same resolver regressions with candidate state produced by the real
  `bind_future_change_candidates` implementation.
- A full offline lifecycle: inferred change -> actual candidate binding ->
  isolated synthetic materialization evidence -> bounded security effects ->
  exact-snapshot subject review. The test performs no target interaction.
- Reviews prepared before materialization are rejected after the snapshot moves.
- Original change provenance remains inferred and attack paths remain unchanged.

## Run locally in an integrated checkout

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src:tests python -m unittest discover -s tests/integration -v
PYTHONPATH=src python scripts/check_safety_canaries.py
```

The integration suite requires the binding and effect modules from PRs #23/#25.
Missing prerequisites are an import failure, never a silently skipped gate.

## CI contract

`lightup-preflight.yml` runs offline diagnostics on Python 3.11 and 3.14.
For draft PR #27 only, it also composes the pinned predecessor heads in a
disposable checkout, runs the combined suite, then the real-producer integration
suite. It never pushes the temporary merge commits or writes a VPS proof receipt.
Remove that temporary job once the predecessors have merged and this PR has
been rebased.

`lightup-ci.yml` remains on `[self-hosted, zcloud, vps]` and verifies the
`vps-bb300bba` hostname. It checks out the exact pull-request head, runs the
unit and integration suites and the shared safety-canary script. The canary uses
a fresh temporary database on every invocation, cleans up its state and captures
CLI output in memory. No shared `/tmp/lightup-web.db` or shared output files
remain, so repeated runs and Python matrix jobs cannot reuse authentication state.

Before merging PR #27: obtain the predecessor VPS proofs, merge #23/#24/#25,
rebase the resolver onto resulting main, and obtain a green exact-head native
VPS run including real-producer integration. Hosted green is not a substitute.

Issue #26 still owns verified subject/effect graph composition. No attack-path
mutation or real-target activation is implemented by this slice.
