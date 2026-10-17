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

## Ownership and release gate

This branch adds two unwired offline reviewers, independent acceptance suites
and this document, solely under ten newly owned paths. No edits to
existing source owners' `src/lightup/*`, other workers' branches, existing
workflows, real clients/targets, live grants, execution handlers, scanning,
remediation, or deployment.

Before *any* LightUp launch: source-owner fixes and integration, fully passing
complete hosted Python 3.11 + 3.14 plus registered permanent
`self-hosted,zcloud,vps` exact-approved-head CI on `vps-bb300bba`,
**separately authenticated client and operator consent with at-use revocation**,
independent privacy/security signoff and explicit HUMAN GO. This reviewer
satisfies **none** of those gates.
