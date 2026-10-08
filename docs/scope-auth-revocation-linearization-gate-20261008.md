# Grant revocation linearization gate (offline review contract)

Status: **review-only**. This document does not establish passing runtime tests or permission to touch a target.

## Invariant

For TARGET_ACTIVE dispatch, a persisted grant must be current, unrevoked, bound to the same client and engagement, and authorize the specific target, capability and risk at the moment authority is consumed. In-memory authorization, prior checks and UI approvals are insufficient substitutes for a fresh durable check. Closing an engagement invalidates all grants, including for a previously started run.

## Required concurrency proof

Use a temporary SQLite database, isolated fake clocks, and fake handlers with a call counter; do not use network targets.

| Case | Deterministic interleaving | Expected observation |
| --- | --- | --- |
| A | resolve grant, revoke grant, attempt handler dispatch | zero target-active handler calls |
| B | resolve grant, close engagement, attempt handler dispatch | zero handler calls |
| C | close engagement, attempt grant issuance | issue refused; zero surviving grant |
| D | issue grant, close engagement | grant is revoked before any later dispatch |
| E | close engagement, reopen, attempt old grant | old grant remains invalid |
| F | resolve grant for tenant A, substitute tenant B or engagement B | reject before handler |
| G | resolve at t0 within validity, dispatch at t1 after expiry | deny at t1 |
| H | retrieve broad stale scope, narrow durable scope, dispatch excluded asset | deny excluded asset |
| I | concurrently revoke/close and dispatch at the final authority boundary | establish a documented linearization point: no handler begins if revocation commits before the final check; if dispatch wins, record the exact order, avoiding claims of retrospective cancellation |

## Evidence required for promotion

- Actual repeatable concurrent tests that exercise the SQLite transaction boundary, not only mocks of the resolver.
- Explicit ordering markers and zero-call assertions for the deny cases.
- Positive control: still-current grant permits one in-scope fake handler call.
- Exact PR head SHA, test command, Python version, CI run URL and self-hosted runner result.
- A reviewer confirms issue #107 / #146 ownership and rebases against the current dependency stack before merge.
- Reject on missing evidence. Neither hosted green nor documentation alone satisfies the self-hosted gate.

## Safety boundaries

No scanning, DNS, socket operations, public targets, exploit requests or authorization broadening. This is a design/acceptance record to be implemented by the existing domain and executor owners.
