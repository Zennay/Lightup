# LightUp M7/ST5 — offline legacy authorization-window integrity review (#1128)

**Status: DRAFT / HOLD / PLAN–LAB ONLY.** This change has zero activation or dispatch authority.

## Actual issue and owner boundary

The legacy `Authorization.is_current` in `src/lightup/models.py` skips falsy, invalid persisted timestamps because it tests `if self.valid_from` and `if self.valid_until`. The legacy `ScopePolicy` then may return `EXPLICIT_HOST/allowed=True` for such an object. See issue #1128 and existing characterization draft #1127. Resolving that executable defect is reserved for the canonical source owners (#100, #107) and requires persisted issuer evidence, live revocation, tenant/asset/capability binding and pre-I/O enforcement.

This standalone **uninstalled** helper `src/lightup/legacy_window_integrity.py` contributes one independently reviewable building block: a narrow, conservative, deterministic timestamp/provenance-shape diagnostic. The returned `LegacyWindowReview` is deliberately not usable as a boolean. Even a positive integrity review **does not establish authentic consent** and must never enter an authorization/allow/execute decision. It does not call `ScopePolicy`, issue a grant, access state or make a request.

## Temporal admission contract

- Exact built-in `Authorization` object; bounded exact built-in owner/reference strings without leading/trailing whitespace, Unicode C* controls/format/surrogates/private-use, Unicode separators other than ordinary ASCII space, NFKC-unstable compatibility characters or oversized values. Text is **unverified** and can be forged.
- `valid_until` is mandatory and finite; `valid_from=None` is accepted for legacy structural compatibility, but both supplied bounds must be exact built-in fixed-offset timezone-aware `datetime` objects.
- Refuse `0`, `False`, `""`, arrays, arbitrary objects, naive datetimes, datetime subclasses, invalid start/end ordering and malformed explicit clocks. Do not use truthiness defaults for `now`.
- Canonicalize to UTC. Start is inclusive; end is **exclusive**, intentionally narrower than the legacy model's inclusive end. Do not broaden actual authorization windows.
- Diagnostic reasons are fixed, non-sensitive codes; no direct exception from comparing malformed values, no input mutation and no network, DB or active target behavior. Noncanonical custom timezone implementations must not have their `tzinfo` callbacks executed. UTC underflow/overflow is a denial, not a crash.
- A structurally valid, invented reference is **still untrusted**. Future integration must re-read trusted persisted issuer-owned authorization and recheck exact tenant, request, target, capability, risk, time window, revocation and approval immediately before any I/O.

## Tests

```sh
PYTHONPATH=src python -m unittest -v tests.test_scope_legacy_window_integrity_20261012
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_legacy_window_integrity_20261012.py' -v
```

The test module exercises real built-in `Authorization`, legacy `ScopePolicy` contrast and a standalone review. The known legacy false-positive is **recorded in open issue #1128**, not asserted as a passing CI invariant: otherwise a future production fix would wrongly break this diagnostic branch. The opt-in reviewer is tested independently of the existing `ScopePolicy` runtime. A green diagnostic test cannot make insecure legacy allow behavior acceptable. No success on this branch can authorize network scans or any target work.

## Release gate

Separate exact-head GitHub-hosted Python 3.11/3.14 unit and real-producer integration evidence from **registered permanent** VPS CI on `vps-bb300bba`. Original owner review, safe latest-main composition, full authorization provenance/revocation integration and explicit human approval remain required. Never merge this as an executable authority, deploy, or suggest the legacy model is fixed merely because the diagnostic passes. Do not modify worker-owned source in #100/#107 or concurrent issue #1173/#1214. No live clients, active scans, credential use, permissions or production state changes.

## Independent W25 regression extension — 2026-10-12

- Reject non-ASCII Unicode spacing/line-separator ambiguity and compatibility-normalization variants in *untrusted provenance labels*, while retaining ordinary ASCII spaces and NFC international text. These are diagnostic shape restrictions, **not issuer verification or spoofing protection**.
- Compare cross-offset instants rather than naive wall time; reject zero-length UTC windows and fixed-offset conversions that underflow or overflow representable UTC bounds.
- Refuse arbitrary custom `tzinfo` implementations *before invoking their callbacks*; no user-supplied clock code runs as a side effect of window parsing.
- Historical unsafe `ScopePolicy` allow behavior is no longer encoded as an assertion that must remain true. The default executable policy is **still vulnerable until source owners repair it**; an independent reviewed window is NOT a grant.
- Scope restricted to the three existing W24 paths on draft #1236; no change to other workers' branches or production source, no CI-hosted success claimed for a superseded commit.
