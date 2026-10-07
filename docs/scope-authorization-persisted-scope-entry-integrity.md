# Persisted scope-entry integrity contract

This acceptance slice pins one execution-time authorization invariant above exact
scope source owner #554 head `4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Durable scope invariant

Persisted grant scope is not valid merely because its three JSON fields decode
to arrays. Execution authority may only be reconstructed from producer-shaped
entries:

- `assets_json` is a **non-empty** array of exact built-in, non-blank strings;
- `excluded_assets_json` is an array containing only exact built-in,
  non-blank strings;
- `allowed_capabilities_json` is a **non-empty** array of exact built-in,
  non-blank strings;
- malformed nested entries deny execution without leaking parser/type errors;
- execution validation never rewrites or normalizes the durable row.

The source repair belongs to the active resolver owner. This child only captures
the missing acceptance boundary.

## Why this is separate

- #479 proves outer JSON shape and `max_risk` reconstruction integrity, not
  nested entry identity.
- #376 covers issuance-time durable asset validation, not later SQLite drift.
- #142/#554 cover execution-time grant safety and the resolver source.
- #562 covers revocation-tuple coherence.
- #575 covers the untrusted runtime `ToolCall.asset`, not persisted allowlist
  entries.

## Acceptance proof

`tests/test_scope_authorization_persisted_scope_entry_integrity.py` includes:

- one canonical current-grant green control;
- empty persisted asset allowlist rejection;
- blank and non-string persisted asset rejection;
- blank and non-string persisted exclusion rejection;
- blank persisted capability rejection;
- an unhashable non-string capability entry proving malformed nested state must
  return `None` rather than leaking `TypeError`;
- before/after durable-state snapshots for every corrupt case.

Against exact #554 source these cases intentionally expose the missing narrow
guard. Canonical behavior must remain green.

## Collision boundary

Tests/documentation only. Do not edit `src/lightup/domain.py`,
`src/lightup/engagements.py`, execution policy/orchestration, #562 files, or
other scope source-owner branches from this slice.

## Safety

Temporary SQLite and in-process authorization resolution only. No DNS/network
I/O, target interaction, scanning, exploit behavior, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
