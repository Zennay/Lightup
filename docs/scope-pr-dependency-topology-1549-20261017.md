# LightUp #1549 — held PR dependency topology (fictional/offline)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. NOT AUTHORIZATION.**

LightUp has many independently owned stacked draft branches. The offline, standalone reviewer checks self-consistency of a *fictional* proposed predecessor DAG before a human reviewer spends time on an invalid merge plan. Distinct from #1540 (cross-worker path collisions), #1456 (ownership), #1309 (real CI evidence), and #1509 (release-fence drift). No existing source owner, runner, worker branch, or installed execution source is changed.

## Input, contract

The CLI takes **one bounded JSON object on stdin** (max 128 KiB):

```json
{"version":1,"root_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[{"id":4,"owner":"worker-a","head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","depends_on":[]},{"id":2,"owner":"worker-b","head_sha":"cccccccccccccccccccccccccccccccccccccccc","base_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","depends_on":[4]}]}
```

1–64 entries; canonical lowercase 40-hex SHAs; exact integer PR IDs; 0–16 predecessors; bounded lowercase ASCII owner labels. Reject additional, missing or duplicate keys, noncanonical types, duplicate PR/head identities, self/missing/cyclic references, stale base claims, and unexpected dependency bases. A root-based item has zero predecessors; a stacked item must explicitly list the candidate whose `head_sha` equals its `base_sha`. Sorted graph waves are advisory, not proof of actual Git ancestry.

Run: `python3 -I -S -B scripts/review_scope_pr_dependencies_1549_offline.py < fictional.json` (no flags or positional arguments; any unexpected argument yields HOLD/exit 2).

Valid fictional graph => `REVIEW_ONLY`, topological `waves`, exit **3**; any invalid/ambiguous/oversize graph => sanitized `HOLD`, empty waves, exit **2**. Never exit 0, never `PASS`. All seven `can_authorize`, `can_scan`, `can_grant`, `can_dispatch`, `can_merge`, `can_deploy`, `can_release` stay hard `false`. No GitHub API, Git, network/DNS, real targets, credentials, grants or handler execution. No proof of origin: reviewers must verify every external GitHub ref/sha and author separately before trusting a proposed plan.

Run tests: `python3 -I -S -B -m unittest discover -s tests -p test_scope_pr_dependencies_1549_offline.py -v`.

## Release hold

A REVIEW_ONLY preview is **not permission to merge or deploy**. True source owner fixes, authenticated separate client/operator consent and at-use revocation, independent security/privacy review, full approved exact-SHA hosted and permanently registered named VPS CI, and explicit HUMAN GO remain required. Do not release, merge, grant, dispatch handlers, or scan real targets.

## W3–W5 verified hardening (2026-10-17)

- **Bounded complete-stream requirement:** reads continue after any positive short read, until genuine EOF. Trailing corrupt chunks, `OSError`, non-byte chunks and >128 KiB are atomic `HOLD`; no `REVIEW_ONLY` based on a valid input prefix. A successful input may be split over multiple reads.
- **Exact admission identity:** zero OIDs (`000…000`) are invalid Git object identities and hold. All admitted keys and values are ASCII identities, so JSON `\\u`-escaped aliases are denied rather than silently canonicalized. Python subclasses of `bytes` are denied before calling user-overridable decode logic.
- **Stress matrix:** 64-node maximum DAGs and multiple deterministic reordered synthetic topologies, malicious duplicated/cyclic/missing predecessor refs and exact 131072-byte positive/131073-byte HOLD boundaries.
- **Dedicated hosted workflow hardening:** only the four explicitly owned new paths are allowed, and each must be an ordinary Git blob mode `100644`; executable `100755`, symlink `120000`, other missing/malformed path modes HOLD before any test. A no-remote/no-hook disposable Git fixture exercises actual regular/executable/symlink Git tree modes. No changes to shared CI or permanent runner.
- These are strictly isolated tests of **fictional review metadata** and the own workflow. They are not client/operator consent or verification of real Git object ancestry and do not permit grants, merges, dispatch, scans or release.

## W7 stdout result boundary

The reviewer must never return `REVIEW_ONLY`/exit 3 merely because a
user-controlled stdout stream *claims* that all bytes were written. In-process
output can be replaced by a custom writer whose integer subclass overrides
comparison. Require `type(write_count) is int` and `write_count == len(line)`
after successful flush; otherwise fail closed with exit 2. The isolated test
includes a deliberately forged `__eq__`/`__ne__` count, plus partial write
and flush-error cases. A pipe failure can still leave a truncated partial line:
consumers must enforce complete JSON and the process exit code, never trust a
prefix. This is offline receipt integrity, not runtime authorization.

## W8 — normalized GitHub draft-PR snapshots (new offline capability)

[Standalone snapshot adapter](../scripts/review_scope_pr_snapshots_1549_offline.py)
accepts a **manually supplied, strictly bounded and explicitly unauthenticated**
normalized subset of GitHub PR metadata. It never queries GitHub, Git, DNS,
networks, the LightUp authorization system or real targets. Reviewers can use
trusted read-only GitHub tools *separately* to collect the exact fields:

```json
{
  "version": 1,
  "root_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "pull_requests": [
    {
      "number": 1550, "owner": "worker-a", "state": "open", "draft": true,
      "head_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "base_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    {
      "number": 1551, "owner": "worker-b", "state": "open", "draft": true,
      "head_sha": "cccccccccccccccccccccccccccccccccccccccc",
      "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ]
}
```

Usage: `python3 -I -S -B scripts/review_scope_pr_snapshots_1549_offline.py < normalized-fictional.json`.
The adapter verifies exact JSON keys/types, lowercase ASCII owner labels,
nonzero 40-hex identities, max 64 distinct open *draft* PRs, a common exact
root, and an unambiguous base-to-head predecessor **within the provided
snapshot only**. Roots have `base_sha == root_sha`; otherwise a predecessor's
`head_sha` must exactly match. No implicit foreign predecessor, cycle,
non-draft, closed PR, extra authority field, repeat, or malformed input is
accepted. Because GitHub's single base reference cannot prove a merge of
multiple parents, this adapter infers **only simple single-parent chains**;
the original synthetic DAG reviewer remains a separate tool for declared
multi-parent review claims.

Valid *fictional* snapshot => `REVIEW_ONLY`/exit 3 with deterministic waves.
Anything ambiguous => generic `HOLD`/exit 2. Nine output flags, including
`source_authenticated` and `merge_plan_approved`, remain **false**,
even with valid input. Never exit 0; no authorization, merging, approvals,
dispatch, scans, grants, production or deployments. The adapter does NOT
prove authentic metadata, actual Git graph ancestry, head freshness,
runtime permissions, or a complete release dependency graph.

Tests: `python3 -I -S -B -m unittest discover -s tests -p 'test_scope_pr_*1549_offline.py' -v`.
The exclusively owned hosted Python3.11/3.14 workflow checks **six**
plain add-only Git mode-100644 files and this combined test suite.

## W9 — byte-bound and canonical advisory receipt fingerprints

The original fictional DAG reviewer now includes `input_sha256` in
**REVIEW_ONLY** receipts: a SHA-256 hash of the *exact accepted raw input
bytes*. It never appears in HOLD, so malformed or untrusted inputs are not
echoed or committed. This fingerprint is useful only to compare snapshots of
the exact same proposal; it is **not** an authentication, endorsement,
authorization, complete graph, or safe-to-merge proof.

The normalized PR-snapshot adapter includes two fingerprints on REVIEW_ONLY:

- `input_sha256` hashes the exact snapshot bytes, including whitespace and
  ordering; any byte-level change results in a different hash.
- `derived_graph_sha256` hashes the **canonically ordered** inferred DAG
  (entries sorted by exact numeric PR ID and JSON keys sorted). Equivalent
  snapshots in a different row order have the same derived-graph fingerprint.
  Any change to root, head, base or dependencies produces a different digest.

The dedicated real-subprocess tests prove different head SHAs can produce the
same advisory wave but different fingerprints. The first implementation
produced different graph digests for reordered equivalent graphs; the
independent negative test demonstrated the defect before the canonical sort
fix. No keys, signatures, customer records or trusted data sources are used.
All review/merge/authorization flags remain false.

A read-only actual-metadata sanity check on 2026-10-17 projected the observed
open draft [#1550](https://github.com/Zennay/Lightup/pull/1550) as an
individual root candidate (REVIEW_ONLY/exit3) and the same candidate combined
under that root with [#1548](https://github.com/Zennay/Lightup/pull/1548)
as HOLD/exit2 because their historical base SHA claims differ. This does not
prove present freshness or that either PR is safe to merge.
