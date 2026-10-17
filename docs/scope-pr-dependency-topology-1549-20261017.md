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
