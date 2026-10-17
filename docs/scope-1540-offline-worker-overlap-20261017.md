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
python3 -I -S -B -m unittest discover -s tests -p 'test_scope_1540_offline_worker_overlap_20261017.py' -q
```

Only **canonical ASCII JSON** is accepted: UTF-8 with no BOM, compact,
sorted keys, no final newline, no alternate escapes, no duplicate object keys;
up to 65,536 bytes. Generate with Python's
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
and write without adding a newline. Exactly:

```json
{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proposals":[{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","branch":"chatgpt/isolated-a","paths":["docs/a.md"],"worker":"scope-a"},{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","branch":"chatgpt/isolated-b","paths":["tests/b.py"],"worker":"scope-b"}],"version":1}
```

The 40-character sample SHA is **fictional**; it must not be mistaken for a
real origin/base attestation. Multiple workers must submit precisely the same
pinned baseline SHA. Reject different, missing, syntactically wrong, uppercase
or unauthenticated baseline claims — but comparing their **claimed** strings
does not authenticate Git ancestry.

## Fail-closed rules

- Exactly 2–32 worker entries, each with 1–64 paths, no duplicate worker
  or case-insensitive branch identity.
- Entire input and each item have an exact field set: no `override`,
  `authorized`, `consent` or other extra claims.
- Only bounded ASCII relative paths, with exact canonical path segments;
  no `..`, `.`, absolute paths, slashes-with-empty-segments, control
  characters, Unicode ambiguity or Windows backslashes.
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
pages, changed rename semantics, *different* bases, untrusted origin or
malicious submitters, the operator must **HOLD externally**, even when the
syntactic preview says REVIEW_ONLY. It does not call the GitHub API, obtain
a branch's complete diff, inspect file modes/symlinks, detect source-level
semantic conflicts or verify any SHA. REVIEW_ONLY must **never** be
interpreted as conflict-free, approval, permission to trigger handlers, or GO.

## Ownership and release gate

This branch adds only a new reviewer, new tests and this document. No edits to
existing source owners' `src/lightup/*`, other workers' branches, existing
workflows, real clients/targets, live grants, execution handlers, scanning,
remediation, or deployment.

Before *any* LightUp launch: source-owner fixes and integration, fully passing
complete hosted Python 3.11 + 3.14 plus registered permanent
`self-hosted,zcloud,vps` exact-approved-head CI on `vps-bb300bba`,
**separately authenticated client and operator consent with at-use revocation**,
independent privacy/security signoff and explicit HUMAN GO. This reviewer
satisfies **none** of those gates.
