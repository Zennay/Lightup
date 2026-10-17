# Scope authorization #1540 — offline parallel-worker overlap HOLD check

**State: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a
standalone, non-authorizing reviewer for *synthetic or separately authenticated*
candidate changed-file listings. It is **not** a GitHub webhook, branch attestation,
approved source head, release authorization, client consent, or scan permission.

## Why this exists

LightUp has dozens of concurrently owned scope, evidence and runtime drafts.
A worker can edit exactly the same file another worker edits, or one worker
can introduce a file at a path that the other treats as a parent directory.
Case-insensitive consumers can collide even where Git's case-sensitive tree
paths differ. An advisory, up-front conflict preview helps avoid wasting runner
capacity and bypassing the active source owner's review. Existing owners' issue
and PR branches are not modified.

## Interface

Opt-in, no external dependencies:

```sh
python3 -I -S -B scripts/review_scope_worker_overlap_offline_1540.py < fictional-manifest.json
# Exit 3 = REVIEW_ONLY (no reported path collision, still no authorization)
# Exit 2 = HOLD (bad, untrusted, mismatched or overlapping input)
# Exit 0 is impossible by design
python3 -I -S -B -m unittest discover -s tests -p 'test_scope_1540_*_20261017.py' -q
```

Only **canonical ASCII JSON** is accepted: UTF-8 with no BOM, compact,
sorted keys, no final newline, no alternate escapes, no duplicate object keys;
up to 65,536 bytes. Generate with Python's
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
and write without adding a newline. Exactly:

```json
{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proposals":[{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","branch":"chatgpt/isolated-a","paths":["docs/a.md"],"worker":"scope-a"},{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","branch":"chatgpt/isolated-b","paths":["tests/b.py"],"worker":"scope-b"}],"version":1}
```

### Version 2: explicit rename/copy/delete operations

Version 1 is unchanged and remains supported. Version 2 gives each worker
a `changes` array rather than a `paths` array; never mix them within one
manifest. A change has exactly `{"op":"add|modify|delete","path":"..."}`
or `{"op":"rename|copy","path":"new-path","from_path":"old-path"}`,
where each value of `op` is **one literal verb**, not the pipe-separated
illustration above. For example:

```json
{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proposals":[{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","branch":"chatgpt/isolated-a","changes":[{"from_path":"src/old.py","op":"rename","path":"src/new.py"}],"worker":"scope-a"},{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","branch":"chatgpt/isolated-b","changes":[{"op":"modify","path":"tests/other.py"}],"worker":"scope-b"}],"version":2}
```

- The **old path and new path** of every rename or copy are both claimed for
  overlap review. A second worker modifying the source or destination returns
  HOLD even when the changed-filenames API provides only the new name.
- Same-worker source/destination aliases and multi-step renames reusing a
  source or destination are conservatively HOLD. This checker is not a
  rename-order simulator and does not prove the Git tree's eventual semantics.
- A deletion also claims its old path, and add/modify claims the target path.
- Each worker may submit 1–64 *operations* (rename/copy expands to two
  identities internally), and the total input remains at most 65,536 bytes.
- A missing `from_path`, an extra `from_path` on a non-rename operation,
  unknown verbs, mixed versions, or extra keys cause atomic HOLD.
- No GitHub rename metadata is discovered or authenticated by this script.
  GitHub changed-filename lists alone are **insufficient** to safely produce
  version 2; the input's old/new lineage must be independently verified first.

The checker uses a bounded, case-folded path-component prefix index rather
than comparing every file against every other file. A 32-worker, 64-path-per-
worker scenario and a multiworker rename/copy scenario have offline positive
and adversarial regression tests.

### Offline normalized-compare ingestion (new)

A second executable CLI converts a **separately obtained, normalized**
GitHub compare snapshot bundle to protocol v2 and applies the *same* path
collision policy, without using a GitHub token, API request, shell or
permission-granting operation:

```sh
python3 -I -S -B scripts/review_scope_compare_snapshots_offline_1540.py < synthetic-compares.json
# Exit 3 REVIEW_ONLY; exit 2 HOLD; NEVER 0, NEVER approval
```

Two committed **purely fictional** ready-to-run compare snapshots exercise both
paths without any GitHub token or external asset:

```sh
python3 -I -S -B scripts/review_scope_compare_snapshots_offline_1540.py < examples/scope1540-compare-review-only.json
# -> REVIEW_ONLY, process exit 3, all six authority fields false
python3 -I -S -B scripts/review_scope_compare_snapshots_offline_1540.py < examples/scope1540-compare-overlap-hold.json
# -> HOLD, process exit 2, all six authority fields false
```

Both fixtures contain fake SHAs and no real client/operator credentials or
approved assets. An independent end-to-end subprocess suite pins the
canonical bytes, fixed no-echo receipts and both exit statuses.

The exact canonical JSON root keys are `base_sha`, `snapshots`,
`version:1`. Each of 2–32 `snapshots` must have exactly:
`worker`, `branch`, `base_sha`, `head_sha`, `compare_status:"ahead"`,
`ahead_by` (strict positive integer), `behind_by:0`, `too_large:false`,
`expected_file_count` (strict integer 1–64) and `files` (exactly that many
entries). Allowed file statuses:
`added`, `modified`, `removed`, `renamed`, `copied`.
Every file has exact keys `status` and `filename`; only `renamed` and
`copied` additionally **require** exact `previous_filename`.

Both the source and destination of renames/copies are included in the
claim index; missing or ambiguous rename ancestry, stale/diverged bases,
unknown status, oversized lists, any extra field, missing count, a
replayed identical `head_sha` claimed by two independent workers, unexpected
byte encoding or cross-worker collision => generic HOLD. The compare
adapter imports **only the known local sibling reviewer** from its fixed
script path. It neither fetches GitHub nor writes any result to disk.

**Important:** `expected_file_count`, `too_large`, commit SHAs and
`compare_status` are still untrusted **caller-provided claims**. The external
operator must authenticate the source GitHub comparisons, confirm they cover
all changes (including pagination, file modes, symlinks and previous paths)
and enforce DRAFT/HOLD separately. Even a valid status from this adapter
does **not** establish ancestry, prove complete or safe integration,
permit a merge, record consent, issue a grant or approve release.

### Dual-view PR/compare consistency (offline, new)

A third, standalone **advisory-only** CLI checks two complementary
*caller-provided* observations before forwarding normalized compare data
to the existing offline path reviewer. It never contacts GitHub, calls
handlers, writes evidence, mints authority, starts CI, or changes a branch:

```sh
python3 -I -S -B scripts/review_scope_pr_compare_pair_offline_1540.py < examples/scope1540-pr-pair-review-only.json
# REVIEW_ONLY, exit 3, six literal false authority flags
python3 -I -S -B scripts/review_scope_pr_compare_pair_offline_1540.py < examples/scope1540-pr-pair-hold.json
# HOLD, exit 2, six literal false authority flags
```

**Input:** canonical compact sorted-key ASCII JSON, maximum 65,536 bytes,
with exact root fields `version:1`, `base_sha`,
`repository_full_name`, `reviews`. Repository identity is a bounded
case-sensitive ASCII `owner/name` reference, *not* an authenticated
GitHub connection. Exactly 2–32 reviews, each with exactly `worker`,
`branch`, `pr`, and `compare`:

- `pr` exact fields: `number` (unique positive exact integer),
  `state:"open"`, `draft:true`, `base_sha`, `head_sha`,
  `head_ref`, `changed_files`, `head_repo_full_name`. The
  branch, pinned base and repository name must match the outer review.
  Forked or mismatched repositories are conservatively HOLD.
- `compare` exact fields: `base_sha`, `head_sha`,
  `repository_full_name`, `status:"ahead"`, positive `ahead_by`,
  zero `behind_by`, `too_large:false` and `files`. Both commit
  references must match the PR and its pinned common base exactly.
  `len(files)` must equal the PR's `changed_files` (1–64).
- A PR number or compared head SHA used by two different workers,
  missing old/new rename provenance, unexpected status, changed branch,
  closed/non-draft PR, trailing JSON bytes, casefold file identity
  collision or any extra field causes atomic `HOLD`.
- The existing version-2 path engine still checks every source and
  destination of renames/copies, and the receipts remain fixed, no-echo
  non-authorizing results (never success code 0).

These **two views can both be forged or stale**. Comparing their claims
neither independently authenticates the GitHub source nor proves commit
provenance, ownership, pagination completeness, file modes, symbolic links,
permission, reviewed code, release criteria or actual client/operator consent.
The source of both snapshots and completeness of the GitHub compare must
be verified *outside* the CLI before an operator can treat even
`REVIEW_ONLY` as meaningful preliminary information. No operation here
can lift LightUp's release HOLD.

The 40-character sample SHA is **fictional**; it must not be mistaken for a
real origin/base attestation. Multiple workers must submit precisely the same
pinned baseline SHA. Reject different, missing, syntactically wrong, uppercase
or unauthenticated baseline claims — but comparing their **claimed** strings
does not authenticate Git ancestry.

## Fail-closed rules

- Exactly 2–32 worker entries, each with 1–64 v1 paths or 1–64 v2
  change operations, no duplicate worker or case-insensitive branch identity.
- Entire input and each item have an exact field set: no `override`,
  `authorized`, `consent` or other extra claims.
- Only bounded ASCII relative paths, with exact canonical path segments;
  no `..`, `.`, absolute paths, slashes-with-empty-segments, control
  characters, Unicode ambiguity or Windows backslashes. Git's `.git`
  internal directory and case-insensitive Windows device names (e.g.
  `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`,
  including extensions) are rejected as unportable change identities.
- Cross-worker case-insensitive **exact path** collisions and file-vs-directory
  **ancestor/descendant** collisions return HOLD. Nonoverlapping children in
  the same directory remain reviewable.
- Duplicate path aliases **and impossible parent/file child paths within a
  single worker**, repeated branches, any inconsistent base and all malformed
  JSON return HOLD atomically.
- Receipt never echoes path names, other user input or error details, and
  its six authority/consent/dispatch/merge/deploy/release flags are always
  the literal JSON boolean `false`.

On missing or invented files in the manifest, truncated GitHub compare
pages, unproven rename source identities, *different* bases, untrusted origin or
malicious submitters, the operator must **HOLD externally**, even when the
syntactic preview says REVIEW_ONLY. It does not call the GitHub API, obtain
a branch's complete diff, inspect file modes/symlinks, detect source-level
semantic conflicts or verify any SHA. REVIEW_ONLY must **never** be
interpreted as conflict-free, approval, permission to trigger handlers, or GO.

## Opt-in worker ownership and protected-source overlay

A **fourth separate non-authorizing offline** reviewer checks that the *exact*
affected paths from every declared PR/compare pair match that worker's claimed
file inventory. It can conservatively HOLD when any affected file is outside
the owner's declared change set, when a supposedly owned file is missing in
the actual compare, or when a changed path touches a caller-designated
protected source path. This is a proposed **review-only** ownership boundary,
not a trusted owner directory, runtime authorization, GitHub installation,
signature verification or source-of-truth policy.

```sh
python3 -I -S -B scripts/review_scope_worker_ownership_offline_1540.py < examples/scope1540-owner-review-only.json
# => REVIEW_ONLY, process exit 3, all six false authority flags
python3 -I -S -B scripts/review_scope_worker_ownership_offline_1540.py < examples/scope1540-owner-hold.json
# => HOLD, process exit 2, all six false authority flags
```

The canonical JSON envelope contains exactly `version:1`,
`repository_full_name`, `base_sha`, `reviews` (the same strict
PR+compare view described above), `ownership` and `protected_paths`.
Every `ownership` item must have exactly `worker`, `head_sha` and
`paths`. The unique worker and exact claimed commit must match one
review entry. `paths` must **exactly equal** the actual changed filename
set **including both old and new paths** of copies and renames; neither
missing paths nor additional invented paths are permitted. Casefold aliases,
nonportable filenames and duplicate worker claims are HOLD.

`protected_paths` must be a nonempty, bounded (1–64) list of exact,
case-insensitively unambiguous relative path identities (not globs or
shell patterns). Both ancestor and descendant collisions are rejected;
unrelated children in the same directory can still be reviewed. A
path claimed as owned by a worker does **not** override a protected path.

### Built-in, non-overridable high-risk HOLD list (new)

The earlier policy relied *only* on caller-supplied `protected_paths`. That
allowed a forged, incomplete inventory to classify new application source,
CI workflow files and checkout safety controls as `REVIEW_ONLY`.
Independent adversarial **RED** tests demonstrated **25 actual failing
subcases** for core/application, `.github/` and build files. Another
**14 actually failing subcases** were reproduced for checkout control and
native safety evidence scripts. This has now been fixed in the standalone
worker-ownership CLI; no live source or other-worker branch was edited.

`CRITICAL_HOLD_PATHS` is a conservative, hard-coded review policy in the
offline worker-ownership reviewer. It does **not** grant any permission.
It always returns `HOLD` for the following paths, their affected
descendants and casefold aliases, even if the caller omits them from the
protected inventory and asserts that a worker owns the file:

- **Application code:** all of `src/lightup/` (including ancestor/descendant
  changes and both rename/copy identities).
- **GitHub control plane:** the entire `.github/` subtree (not only CI
  workflow YAML).
- **Build/release:** `pyproject.toml`, `setup.py`, `setup.cfg`,
  `tox.ini`, `uv.lock`, `poetry.lock`, `requirements.txt`,
  `Dockerfile`, `Makefile`, `.pre-commit-config.yaml`.
- **Checkout control:** `.gitattributes`, `.gitmodules`, `.lfsconfig`,
  `.gitignore`. Git-internal `.git` segments are rejected upstream.
- **Safety evidence scripts:** `scripts/check_safety_canaries.py`,
  `scripts/review_scope_history_against_checkout_offline.py`,
  `scripts/review_scope_registry_history_offline.py`,
  `scripts/review_scope_capability_registry_offline.py`,
  `scripts/export_scope_capability_registry_offline.py`,
  `scripts/render_scope_registry_history_offline.py`.
- **The offline reviewers themselves:** `scripts/review_scope_worker_overlap_offline_1540.py`,
  `scripts/review_scope_compare_snapshots_offline_1540.py`,
  `scripts/review_scope_pr_compare_pair_offline_1540.py` and
  `scripts/review_scope_worker_ownership_offline_1540.py`.
  No advisory checker may silently classify a change to its own parser
  or its trust dependencies as `REVIEW_ONLY`.

The reviewer checks exact path-segment ancestry, not indiscriminate string
prefixes; e.g. `src/lightup_fake/file.py` and
`pyproject.toml.backup` are distinct and do not trip these literal rules.
A change is **only** considered for `REVIEW_ONLY` if it passes these
conservative rules *and* the explicit caller-provided protections and all
other PR/ownership consistency checks. The list is explicitly **not**
complete: no claim is made about symlinks, Git file modes, credentials,
provenance, authenticity, safe target scope, grants, or release eligibility.
Protected source changes require independent review: `HOLD` is not a
permanent denial or a substitute for human judgement.

A runnable canonical synthetic negative fixture makes the distinction
reproducible: `examples/scope1540-invariant-critical-path-hold.json`
claims an otherwise disjoint workflow change and an unrelated protected
inventory. Nevertheless:

```sh
python3 -I -S -B scripts/review_scope_worker_ownership_offline_1540.py < examples/scope1540-invariant-critical-path-hold.json
# -> HOLD, exit 2, no user-provided paths echoed, six false authority fields
```

The corresponding dedicated subprocess and byte-integrity regressions
are part of `test_scope_1540_*_20261017.py` discovery.

A fresh read-only compare of draft PR #1537 and #1539 shows they each
touch at least one `.github/workflows/` file. The formerly
`REVIEW_ONLY` non-overlap preview now **correctly reports HOLD/exit 2**
even though their filenames do not conflict and the caller-provided
protected list was deliberately unrelated. This does not edit those PRs
or authorize their release.

**Provenance limitations:** all ownership identities, protected paths,
PR data, comparisons and SHAs are supplied by the caller. A malicious or
mistaken caller can omit an important protected path or forge all inputs.
The only trustworthy protection is an external, independently maintained
scope/owner inventory and independently verified GitHub evidence, enforced
separately. `REVIEW_ONLY` means only that the supplied *claims* pass these
syntactic checks; never verified ownership, authorization, consent, release,
merge eligibility or a successful independent safety assessment.

Two synthetic committed no-credentials samples demonstrate both statuses;
regressions cover 16 workers × 16 file claims, case-insensitive protected
aliases, rename-source accounting, fake extra/missing paths, tampered SHA,
no-echo CLI receipts and oversized fail-closed input.

## Ownership and release gate

This branch adds four unwired offline reviewers, independent acceptance suites,
synthetic examples and this document, exclusively in own new files. It
never changes original source-owner production code, other-worker paths,
existing workflow files or the system runner. No edits to
existing source owners' `src/lightup/*`, other workers' branches, existing
workflows, real clients/targets, live grants, execution handlers, scanning,
remediation, or deployment.

Before *any* LightUp launch: source-owner fixes and integration, fully passing
complete hosted Python 3.11 + 3.14 plus registered permanent
`self-hosted,zcloud,vps` exact-approved-head CI on `vps-bb300bba`,
**separately authenticated client and operator consent with at-use revocation**,
independent privacy/security signoff and explicit HUMAN GO. This reviewer
satisfies **none** of those gates.
