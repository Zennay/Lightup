# LightUp — offline grant-amendment narrowing preview (2026-10-14)

**Posture:** INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD. This is a **new, uninstalled reviewer**. It neither authenticates consent nor alters LightUp authorization. No merge, deployment, target connections, runtime permission or automatic promotion.

## Why it exists

An amendment can accidentally widen a previously discussed grant without changing its displayed title. The operator needs a quiet, privacy-minimal comparison that highlights **which dimension may have expanded**, not an unsafe "approved" verdict.

This standalone tool is a distinct *two-snapshot comparison* for [open issue #951](https://github.com/Zennay/Lightup/issues/951) and [#953](https://github.com/Zennay/Lightup/issues/953). It does **not** replace actual ToolExecutor/live persisted grant validation owned by [PR #107](https://github.com/Zennay/Lightup/pull/107), authorization envelope source integration [#1023](https://github.com/Zennay/Lightup/issues/1023), or self-asserted cross-lane CI proof verification [#1429](https://github.com/Zennay/Lightup/issues/1429).

## Try with **fictitious** metadata only

The tool reads at most 16,384 bytes from **local regular-file or FIFO stdin**; sockets, devices and directories are denied. Its read uses a strict 2-second absolute deadline and requires EOF: an incomplete or even a complete JSON document sent over a pipe whose writer remains open yields HOLD. The reader uses temporarily nonblocking FD 0 (to prevent the select/read second-reader race), attempts to restore the inherited blocking state on every path, and checks file kind, device and inode again after EOF. For regular files it requires a positive declared size (up to 16 KiB), an inherited cursor exactly at byte zero, and an EOF after **exactly** that many bytes. It also checks file length, mtime and ctime against the initial snapshot: a shifted cursor, short read, size-less virtual file or changed input is atomically HOLD, not an accepted partial read. These are bounded userland heuristics, **not** proof of original file identity, consent, a transactional file lock or an OS sandbox. If using concurrent readers, create isolated private descriptors. In a local disposable checkout, run:

    python -B scripts/review_scope_grant_amendment_20261014_offline.py --stdin-json < synthetic-review.json
    python -B -m unittest discover -s tests -p 'test_scope_grant_amendment_20261014_offline.py' -v

**CLI safety:** the only accepted argument sequence is exactly `--stdin-json` once. Missing, duplicate, unknown or malformed arguments exit 2 **without reading stdin and without echoing any argv/pipe content to stdout or stderr**. This intentionally does not provide generic argparse help/error text, which could otherwise disclose a secret supplied as an unknown argument.

JSON input must have exactly three fields: `schema` with the literal value `lightup.grant-amendment-review.v1`, plus `before` and `after`.

Each snapshot must contain exactly these keys:

| Key | Format | Narrowing rule |
| --- | --- | --- |
| `grant_id`, `client_id`, `engagement_id`, `approved_by`, `reference` | Opaque bounded ASCII identifier, never displayed | All must match exactly. |
| `assets` | Both snapshots: empty allowed as the actual model's no-target state; otherwise 1–32 distinct canonical lowercase opaque identifiers | `after` must be a subset of `before`; an already-empty before-list can *only* remain empty. No asset may reappear. |
| `excluded_assets` | At most 32 distinct canonical lowercase opaque identifiers | `after` must be a superset of `before`. |
| `capabilities` | Before: **empty means unrestricted** in real `ScopeDefinition`, or 1–32 distinct canonical lowercase capabilities. After: **1–32 only**, never empty. | An originally unrestricted grant may be narrowed to any explicit nonempty after-list. Otherwise `after` must be a subset of `before`; an empty after-list is always HOLD because it removes the restriction. |
| `max_risk` | Literal **ASCII JSON integer tokens** `0`, `1`, `2`, `3` or `4` only, **not** bool, `-0`, decimal/exponent spelling or huge integer; 5 (destructive lab) refused | Must stay unchanged or decrease. |
| `valid_from`, `valid_until` | Exact RFC3339 UTC `YYYY-MM-DDTHH:MM:SSZ`, **ASCII `[0-9]` digits only**, increasing | Start not earlier; end not later; no non-ASCII decimal glyphs, offsets, abbreviations or fractional seconds. |
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

The input parser refuses oversized buffers, duplicate object keys (including escaped aliases), non-finite numbers, floating-point values, **negative-zero `-0` (which Python would normalize to int `0`), noncanonical or oversized numeric spellings**, invalid UTF-8, BOM, scalar roots, trailing documents, unexpected keys, duplicate member entries, and wrong Python/JSON primitive types. The timestamp format gate uses literal ASCII `[0-9]`, not the Unicode-aware regex `\\d`, rejecting non-ASCII decimal glyphs before datetime parsing. Every rejection yields generic HOLD with no submitted identifiers or values copied to a receipt.

**Complete target revocation and serial no-target reviews:** `after.assets: []` is a legitimate structural narrowing whether the original grant had targets or was already fully revoked. The actual LightUp `ScopeDefinition.allows_asset` returns false for every target if `assets=()`. When `before.assets: []`, only an empty after-list can remain `REVIEW_ONLY`; restoring even a single target is **HOLD**. A zero-asset proposal can yield `REVIEW_ONLY`, but **never an authorized or dispatch-enabled receipt**; every independent widening of identity, capabilities, exclusion removals, risk, window or retest permission remains HOLD. Crucially, `after.capabilities: []` continues to be invalid because real `ScopeDefinition` interprets that as unrestricted capabilities, not revocation. These differ deliberately.

**Unrestricted capability baseline:** `before.capabilities: []` represents the real LightUp model's **all tools allowed** rule. The only safe amendment reviewed from such a baseline supplies a **nonempty explicit** `after.capabilities` list. The offline comparator now treats that as a structural narrowing instead of mistaking it for an added-capability widening. In contrast, `after.capabilities: []` is always `HOLD`, even when the original was unrestricted. A deterministic 64-case composition matrix proves that this legitimate restriction cannot hide any concurrent expansion of target assets, risk, exclusions, validity window, approver identity or retest permission. Synthetic real-model `ScopeDefinition.allows_capability` assertions independently verify the baseline semantics. Even the resulting `REVIEW_ONLY` receipt has all six authorization/release flags literally false, and the tool is not connected to the live grant issuance path.

**Serial narrowing:** a synthetic three-stage test (original → no-target revocation → even tighter capability/risk limits) checks each change and the composed original-to-final comparison. No-target `before` now remains reviewable, while any later asset resurrection or unrelated identity/risk/time/recurring-retest permission widening is still HOLD. This is a structural test only, never proof that a production revocation was persisted or distributed.

## Interpretation

- **HOLD (exit 2)** means malformed input or a possible widening (including switched tenant/engagement/provenance reference). The receipt lists *only generic dimensions* such as `risk` or `window`; no asset/client/reference values are printed.
- **REVIEW_ONLY (exit 3)** means this submitted pair was *structurally* non-widening. **It is not approval or a runtime authorization decision.**
- **There is deliberately no exit 0.** All six `authorized`, `permit_issued`, `dispatch_enabled`, `merge_approved`, `deploy_approved`, and `release_approved` fields are literally false for every outcome.

This model only compares **literal self-reported strings**, not real DNS, CIDRs, aliases, wildcards, asset inventories or provenance signatures. Empty **after** `capabilities` is denied because the existing `ScopeDefinition` treats it as unrestricted; an empty **before** capability list is a legitimate unrestricted source that may be narrowed to explicit tools. Even non-widening input may still be untrusted, expired, revoked, malformed against true production rules or unauthorized. Superset exclusions and subset assets do not independently establish safe reachability.

## Current optional hardening: filedescriptor postconditions and model agreement

After reading stdin the reviewer does **not** accept `REVIEW_ONLY` if the inherited fd0 blocking flag differs from its initial state, including when a simulated `os.set_blocking` call silently fails. Receipt delivery likewise refuses success when fd1 blocking restoration does not actually take effect. An accepted receipt is issued through at most one positive `os.write` (within the receipt's 512-byte envelope); a short write never triggers a follow-up fragment that another process could interleave. In that exceptional case the process returns nonzero, although bytes already written cannot be rolled back. Immediately before each bounded write, fd1 device/inode/file-kind must still match the local pipe or TTY originally inspected; detected destination replacement fails closed without sending to the replacement. These checks narrow accidental redirection and shared-FD leaks but cannot turn mutable process filedescriptors into OS security capabilities or prevent all time-of-check/time-of-use races.

A deterministic 256-case test matrix exercises combinations of four safe narrowing changes and four attempted scope widenings. Additionally a **2,048-case differential matrix uses real in-memory `AuthorizationGrant`/`ScopeDefinition` methods** across all four combinations of unrestricted/explicit original capabilities and originally-revoked/populated asset lists, then a bounded lattice of synthetic assets, capabilities, UTC instants (including original-window boundaries), and requested risk levels: every `REVIEW_ONLY` case must prove no newly permitted request compared with the original model grant, while every proposed literal widening stays `HOLD`. This is an offline test oracle, **not proof of trusted authorization**. Independent synthetic tests instantiate **real installed LightUp `AuthorizationGrant`, `ScopeDefinition` and `RiskLevel` dataclasses** to compare the offline narrowing decision with the actual model's asset exclusions, capability admission, risk and UTC windows. No grant is issued/persisted, no `ExecutionPolicy` or `ToolExecutor` is called, and this does not validate operator consent, trusted issuer, live revocation or destination binding.

## Actual release/activation gates

Still require: trusted registered operator and customer authorization, tenant/asset/capability provenance and current persisted scope, risk and approval evaluation, exact destination binding at each execution attempt, revocation check immediately before external I/O, independent security/privacy review, exact immutable-head GitHub-hosted CI **and separate registered permanent VPS** test evidence, and explicit human merge/release approval. Do not substitute this local review receipt for any of them.

**Owned paths on this draft only:** `scripts/review_scope_grant_amendment_20261014_offline.py`, `tests/test_scope_grant_amendment_20261014_offline.py`, and this document. No production `src/lightup/*`, other worker test fixtures, workflows, runners, secrets, client payloads, persistence or network interactions are modified.
