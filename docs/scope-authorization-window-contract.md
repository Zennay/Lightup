# Scope authorization window contract

Issue: #341

This proof freezes the temporal semantics of the legacy `Authorization` object
without modifying any active scope, planner, activation, execution-policy,
domain, or web ownership.

## Contract

- `valid_from` and `valid_until` are inclusive when present.
- Evaluation before `valid_from` or after `valid_until` is not current.
- An inverted window (`valid_from > valid_until`) cannot become current at any
  evaluated instant.
- A public explicit-host target with an inverted authorization window is denied
  by `ScopePolicy`; it does not become executable through malformed chronology.
- A naive evaluation clock is rejected. Authorization time comparisons therefore
  cannot silently mix timezone-aware and timezone-naive evaluation state.

## Safety boundary

This slice is proof-only. It performs no DNS or network I/O, target interaction,
scanning, capability execution, remediation/retest execution, deployment, or
attack-path mutation. It adds no execution authority.

## Collision boundary

Only these new files belong to this slice:

- `tests/test_scope_authorization_window_contract.py`
- `docs/scope-authorization-window-contract.md`

Existing scope/authorization source and tests remain untouched so active
scope-authorization branches retain ownership of their files.
