# Scope authorization: parallel PR file-ownership preflight

This **read-only** helper answers one narrow question before a worker writes files:
*Does another open LightUp PR already modify the same file, or a file beneath
the directory I intend to own?* It does not inspect other workers' unpublished
branches, detect semantic conflicts across different files, authorize a target,
approve an assessment, issue grants, or establish readiness to merge/deploy.

## Usage (operator / safe runner)

Supply a GitHub read token in `GITHUB_TOKEN` (or `GH_TOKEN`); never log it.
The code only makes GET requests to `https://api.github.com` and never
interacts with assessment targets or mutable repository endpoints.

```sh
python scripts/check_scope_pr_overlap.py \
  --repo Zennay/Lightup \
  --path src/lightup/execution_policy.py \
  --path tests/my_new_scope_test.py

# If checking files on your OWN existing PR, explicitly exclude only that PR:
python scripts/check_scope_pr_overlap.py \
  --path docs/my_scope_notes.md --ignore-pr 123
```

**Exit statuses:** `0` means no collision among *completely fetched* open PRs
at this instant; `3` means collision(s) found; `2` means **UNKNOWN** due
to incomplete pagination, API/rate-limit errors or invalid inputs. Never interpret
UNKNOWN as a pass. All three emit one JSON object with `status` of `clear`,
`overlap` or `unknown`. Review `collisions[*].pr`, `candidate`,
`changed_paths` and `url`. The helper checks renamed files under both old
and new paths, counts draft PRs, and scans **all** open PRs, not just PRs with a
particular title. Path matching is exact, except a trailing `/` explicitly
requests a directory prefix.

The helper reads GitHub pages of 100 items and refuses a definitive answer if
a configured pagination bound is exhausted. If GitHub has too many open PRs or
a file list cannot be completely read, **do not proceed based on the report**.
A large repository may need a read-token with sufficient API budget; do not
reduce completeness to make the command pass. The script also reads the **open
PR list and immutable head SHAs twice** (before and after file inspection);
if the collection or any head changed during the scan, the result is
`unknown`, not `clear`. This is a race detector, not an atomic GitHub snapshot.

## Work-ownership rules

1. Choose a unique branch and new test/docs filenames. Before writing source,
   run the helper with all intended files/directories. Do not ignore another
   worker's PR. Coordinate overlaps with the source owner rather than changing
   their branch.
2. Treat the report as a volatile snapshot. Recheck immediately before writing
   and again before raising a PR; unpublished branches and commits racing after
   the snapshot are not visible. Prefer appending isolated new files when
   production modules already have open owners.
3. For this LightUp lane, `src/lightup/ai/orchestration.py` and the real
   executor are controlled by [#107](https://github.com/Zennay/Lightup/pull/107);
   web app/security sources have active [#182](https://github.com/Zennay/Lightup/pull/182)
   and [#202](https://github.com/Zennay/Lightup/pull/202) owners. These are
   examples, **not** an exhaustive/static authority list. Use live PR results.
4. Keep all LightUp real-target activation **DRAFT/HOLD**. PR overlap
   clearance is never consent, capability approval, scope verification,
   destination ownership proof, final pre-I/O revocation, or permanent VPS
   acceptance. Never use the script to initiate target requests.

## Offline acceptance

```sh
python -m unittest discover -s tests -p test_scope_pr_overlap_preflight.py -v
```

Synthetic tests inject an in-memory GitHub GET opener: exact/path-prefix matches,
renames, self-ignore, non-overlaps, second-page discovery, truncated PR/file
pages, HTTP errors, malformed records and oversized PR sets. No GitHub credential,
socket, target traffic, grant, or repository mutation is needed for tests.

This branch provides coordination tooling only. Hosted CI checks and the
**canonical permanent self-hosted VPS** checks must both pass on the same
exact reviewed commit before merge; independent owner review remains required.
