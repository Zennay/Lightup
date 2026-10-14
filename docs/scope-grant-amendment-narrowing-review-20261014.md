# LightUp — offline grant-amendment narrowing preview (2026-10-14)

**Posture:** INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD. This is a **new, uninstalled reviewer**. It neither authenticates consent nor alters LightUp authorization. No merge, deployment, target connections, runtime permission or automatic promotion.

## Why it exists

An amendment can accidentally widen a previously discussed grant without changing its displayed title. The operator needs a quiet, privacy-minimal comparison that highlights **which dimension may have expanded**, not an unsafe "approved" verdict.

This standalone tool is a distinct *two-snapshot comparison* for [open issue #951](https://github.com/Zennay/Lightup/issues/951) and [#953](https://github.com/Zennay/Lightup/issues/953). It does **not** replace actual ToolExecutor/live persisted grant validation owned by [PR #107](https://github.com/Zennay/Lightup/pull/107), authorization envelope source integration [#1023](https://github.com/Zennay/Lightup/issues/1023), or self-asserted cross-lane CI proof verification [#1429](https://github.com/Zennay/Lightup/issues/1429).

## Try with **fictitious** metadata only

The tool reads at most 16,384 bytes from **local regular-file or FIFO stdin**; sockets, devices and directories are denied. Its read uses a strict 2-second absolute deadline and requires EOF: an incomplete or even a complete JSON document sent over a pipe whose writer remains open yields HOLD. The reader uses temporarily nonblocking FD 0 (to prevent the select/read second-reader race), attempts to restore the inherited blocking state on every path, and checks file kind, device and inode again after EOF. For regular files it also checks file length, mtime and ctime against the initial snapshot: a changed input is atomically HOLD, not an accepted partial read. These are bounded userland heuristics, **not** proof of original file identity, consent, a transactional file lock or an OS sandbox. If using concurrent readers, create isolated private descriptors. In a local disposable checkout, run:

    python -B scripts/review_scope_grant_amendment_20261014_offline.py --stdin-json < synthetic-review.json
    python -B -m unittest discover -s tests -p 'test_scope_grant_amendment_20261014_offline.py' -v

JSON input must have exactly three fields: `schema` with the literal value `lightup.grant-amendment-review.v1`, plus `before` and `after`.

Each snapshot must contain exactly these keys:

| Key | Format | Narrowing rule |
| --- | --- | --- |
| `grant_id`, `client_id`, `engagement_id`, `approved_by`, `reference` | Opaque bounded ASCII identifier, never displayed | All must match exactly. |
| `assets` | Nonempty list of at most 32 distinct canonical lowercase opaque identifiers | `after` must be a subset of `before`. |
| `excluded_assets` | At most 32 distinct canonical lowercase opaque identifiers | `after` must be a superset of `before`. |
| `capabilities` | Nonempty list of at most 32 distinct canonical lowercase opaque identifiers | `after` must be a subset of `before`. |
| `max_risk` | Exact integer 0–4, **not bool**; 5 (destructive lab) refused | Must stay unchanged or decrease. |
| `valid_from`, `valid_until` | Exact RFC3339 UTC `YYYY-MM-DDTHH:MM:SSZ`, increasing | Start not earlier; end not later. |
| `recurring_retest_allowed` | Exact JSON boolean | A false value may not become true. |

Example **synthetic** grant snapshot, use this identically under `before` and `after`:

    {
      "grant_id": "demo-only-01",
      "client_id": "client-example",
      "engagement_id": "eng-example",
      "approved_by": "operator-demo",
      "reference": "test-only",
      "assets": ["lab-a.example"],
      "excluded_assets": ["lab-b.example"],
      "capabilities": ["http_headers"],
      "max_risk": 1,
      "valid_from": "2026-10-14T00:00:00Z",
      "valid_until": "2026-10-15T00:00:00Z",
      "recurring_retest_allowed": false
    }

The output receipt is independently sealed against forged keys, approval flags, status/reason combinations, and unrecognized widening dimensions *before opening stdout*. It is at most **512 ASCII bytes**, one JSON line. The CLI writes only to a local FIFO/pipe or terminal, never an inherited socket, regular file, directory, or non-terminal character device. Delivery has an absolute **2-second write deadline**; a full or broken output pipe exits nonzero. When switching inherited POSIX stdout to nonblocking mode, it attempts to restore the original shared pipe mode even on failure. This is application-level defensive handling, **not an OS sandbox**; transient shared flags can still affect simultaneous parent writers, so use private pipes for isolation.

The input parser refuses oversized buffers, duplicate object keys (including escaped aliases), non-finite numbers, floating-point values, invalid UTF-8, BOM, scalar roots, trailing documents, unexpected keys, duplicate member entries, and wrong Python/JSON primitive types.

## Interpretation

- **HOLD (exit 2)** means malformed input or a possible widening (including switched tenant/engagement/provenance reference). The receipt lists *only generic dimensions* such as `risk` or `window`; no asset/client/reference values are printed.
- **REVIEW_ONLY (exit 3)** means this submitted pair was *structurally* non-widening. **It is not approval or a runtime authorization decision.**
- **There is deliberately no exit 0.** All six `authorized`, `permit_issued`, `dispatch_enabled`, `merge_approved`, `deploy_approved`, and `release_approved` fields are literally false for every outcome.

This model only compares **literal self-reported strings**, not real DNS, CIDRs, aliases, wildcards, asset inventories or provenance signatures. Empty `capabilities` is denied because the existing `ScopeDefinition` treats it as unrestricted. Even non-widening input may still be untrusted, expired, revoked, malformed against true production rules or unauthorized. Superset exclusions and subset assets do not independently establish safe reachability.

## Actual release/activation gates

Still require: trusted registered operator and customer authorization, tenant/asset/capability provenance and current persisted scope, risk and approval evaluation, exact destination binding at each execution attempt, revocation check immediately before external I/O, independent security/privacy review, exact immutable-head GitHub-hosted CI **and separate registered permanent VPS** test evidence, and explicit human merge/release approval. Do not substitute this local review receipt for any of them.

**Owned paths on this draft only:** `scripts/review_scope_grant_amendment_20261014_offline.py`, `tests/test_scope_grant_amendment_20261014_offline.py`, and this document. No production `src/lightup/*`, other worker test fixtures, workflows, runners, secrets, client payloads, persistence or network interactions are modified.
