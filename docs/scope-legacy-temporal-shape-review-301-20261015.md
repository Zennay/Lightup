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
- The reviewer detects missing validity attributes and observable in-call
  rebinding of either validity field, including rebinding of a nominally
  frozen dataclass through `object.__setattr__`. This is only best-effort
  drift detection, **not** an atomic snapshot or a concurrency lock.
- The reviewer does not read system time, files, persistent data or network and
  has no real target contact. It is an **advisory snapshot only**, not an
  authorization assertion after return.

## Run locally

```bash
PYTHONPATH=src python -m unittest -v tests/test_scope_legacy_temporal_shape_review_301.py
# or, with tests/ not packaged:
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_legacy_temporal_shape_review_301.py' -v
```

The dedicated suite verifies strict type/offset admission, spoofing refusal,
inclusive window boundaries, opaque no-authority receipts, no-I/O tripwires,
and denial of forged receipt statuses.

## W2: optional bounded atomic batch review

`review_legacy_authorization_batch((authorization_a, ...), observed_at=now)`
accepts **only an exact tuple of 1–32 exact legacy Authorization objects** and
an explicit exact built-in timestamp. Every member must satisfy the same
strict timestamp invariants as the single-item reviewer.

- Any malformed input, invalid member, expiry/not-before failure or incomplete
  object produces a **single generic HOLD/invalid_batch** receipt; no per-item
  verdicts, partial-success count, owner, approval text or target is returned.
- Only a completely canonical synthetic batch returns
  **REVIEW_ONLY/temporal_shape_only**. Both paths carry six literal False
  authority/release flags; they never approve an engagement or capability.
- The reviewer takes a temporal reference snapshot for each member and checks
  all snapshots again before returning. Observable mutation of an earlier
  claim while later claims are inspected results in opaque HOLD.
- This is not a transaction, lock, concurrency guarantee or proof that windows
  remain stable after returning. It deliberately has no target, network,
  database, filesystem, clock, grant or execution integration.
- Test matrix: 1/2/16/32 exact-positive sizes, size 0/33 and forged tuple
  rejection, every invalid-member position across 1/2/8/32 inputs, 150
  deterministically shuffled bad-member permutations, in-call rebindings
  and real file/network/process tripwire controls.

## W4: stored-field identity cannot be spoofed by an attribute getter

The single-item reviewer pins exact identity between the **materialized
instance dictionary values** and the values returned by attribute getters.
It checks this twice, with the final dictionary read **after** the last
getter invocation. A patched getter that returns a fabricated valid end-time
while the actual stored field is `False`, or a getter that rebinds a stored
field after an earlier valid comparison, now returns opaque HOLD. The two
synthetic regressions use `unittest.mock.patch.object` and do not change
installed `Authorization.is_current` or any source-owner files.

This is a defensive, opt-in review contract. It is not proof of cross-thread
atomicity or safety after return, and it cannot authorize a scan or customer
engagement.

## W5: bypass user-patched storage accessors

Both single and 1–32-member synthetic review now read materialized instance
storage through the built-in `object.__getattribute__(auth, "__dict__")`
primitive. This bypasses a potentially monkeypatched `Authorization.
__getattribute__` that could return **both** a forged dictionary and a
forged expiry datetime. A new negative control supplies precisely that
dual-spoofing case and expects opaque HOLD for single and batch review;
a second positive control confirms that a fake `__dict__` getter cannot
overwrite a genuinely unchanged valid stored window. The offline static
source-effect canary permits only that exact built-in storage read, not
arbitrary private field reads or user-defined getters.

This diagnostic still does not establish trustworthy source provenance,
operator/client consent, a concurrency lock or installed authorization.
The original source owner must independently repair the installed method.

## Hard gate: not a production fix

This does **not** repair `Authorization.is_current()`. Release requires the
original model owner to perform runtime exact-type and aware-boundary checks
**before** any activation/scope decision, rerun known issue #301/#731/#733
expected-RED tests as ordinary passing assertions, and independently verify
real consent provenance (#177), durable revocation (#347), the installed
ingress/egress boundary and permanent VPS runner, followed by security/privacy
and human approval. Keep all branches DRAFT/HOLD; **no merge, deployment,
real grants, scans or live target dispatch from this receipt.**
