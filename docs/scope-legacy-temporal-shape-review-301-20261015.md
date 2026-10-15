# LightUp #301 — independent legacy authorization timestamp review

**2026-10-15 · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**

## Purpose

`Authorization.is_current()` in `src/lightup/models.py` still uses truthiness
for `valid_from`/`valid_until`, so a falsy non-datetime (e.g. `0`,
`False`, `""`) may silently become an unbounded interval. This is an
**unfixed production authorization defect**, tracked in #301, with legacy model
source ownership retained by PR #100/#104. Existing RED acceptance tests must
not be marked fixed by this diagnostic.

The new opt-in `lightup.legacy_temporal_shape_review_301` checks *fictional*
in-memory legacy `Authorization` values only. It is a strictly **non-authorizing
reference and reviewer aid**, not automatically wired into any installed
permission, web ingress, scanner, ToolExecutor, ScopePolicy or ActivationGate.

## Precise admission contract

- Input must be **exact** `Authorization`, not a subclass or dictionary;
  caller must explicitly supply an **exact** built-in `datetime` instant.
- Each existing validity endpoint must be either `None` or an exact built-in
  aware `datetime`; timezone must be the exact built-in `datetime.timezone`
  (UTC or a fixed offset). Noncanonical timezone types, including a potentially
  valid `zoneinfo.ZoneInfo`, return HOLD for manual review because they can
  involve outside code; this diagnostic is intentionally conservative.
- `valid_from > valid_until` and an entirely unbounded pair receive HOLD.
  One-sided windows are reviewed as shapes, not permits.
- Inclusive endpoints and canonical UTC/fixed-offset equivalence are preserved.
  A microsecond beyond the end or before the start returns HOLD.
- Explicit falsy/malformed `observed_at`, subclass datetimes,
  forged `Authorization` subclasses and adversarial timezone methods are
  refused without invoking attacker-controlled datetime/tz comparison hooks.
- The only possible statuses are `HOLD` and `REVIEW_ONLY`. Every receipt
  includes six literal `False` fields: authorization_verified, permit_issued,
  execution_enabled, target_dispatch_allowed, merge_approved, release_approved.
  No owner, reference, asset, identity or raw timestamp is reflected.
- The reviewer does not read system time, files, persistent data or network and
  has no real target contact. It is an **advisory snapshot only**, not a
  concurrency lock and not an authorization assertion after return.

## Run locally

```bash
PYTHONPATH=src python -m unittest -v tests/test_scope_legacy_temporal_shape_review_301.py
# or, with tests/ not packaged:
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_legacy_temporal_shape_review_301.py' -v
```

The dedicated suite verifies strict type/offset admission, spoofing refusal,
inclusive window boundaries, opaque no-authority receipts, no-I/O tripwires,
and denial of forged receipt statuses.

## Hard gate: not a production fix

This does **not** repair `Authorization.is_current()`. Release requires the
original model owner to perform runtime exact-type and aware-boundary checks
**before** any activation/scope decision, rerun known issue #301/#731/#733
expected-RED tests as ordinary passing assertions, and independently verify
real consent provenance (#177), durable revocation (#347), the installed
ingress/egress boundary and permanent VPS runner, followed by security/privacy
and human approval. Keep all branches DRAFT/HOLD; **no merge, deployment,
real grants, scans or live target dispatch from this receipt.**
