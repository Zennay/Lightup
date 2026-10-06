# Authorization time-window boundary contract

Issue: #295

This tests/docs-only contract pins the temporal semantics of the legacy
`Authorization` object used by `Target` / `ScopePolicy` without changing
production source.

## Security invariant

Authorization validity is a closed interval when a boundary is present:

- `valid_from` is inclusive;
- `valid_until` is inclusive;
- an instant before `valid_from` is not current;
- an instant after `valid_until` is not current;
- equivalent timezone-aware instants compare as the same instant;
- a timezone-naive evaluation instant is rejected;
- an inverted interval never produces a current authorization.

For explicitly scoped public hosts, a future or expired authorization remains
denied by the existing authorization-time gate. Temporal validity is necessary
for public scope but is not itself target or capability authority.

## Compatibility boundary

The test fixture inspects the `Authorization` dataclass fields and supplies
the exact target asset only when the active model includes PR #100's
`assets` field. This keeps the temporal proof compatible with both exact
current `main` and the active #100 legacy-authorization hardening without
modifying or claiming #100-owned source.

## Safety

All checks are deterministic datetime comparisons or in-memory
`ScopePolicy.decide()` calls. No DNS, sockets/HTTP, target interaction,
scanning, execution, remediation/retest execution, deployment or attack-path
mutation is performed.

This branch is intentionally tests/docs-only and remains branch-only until
exact-head hosted and canonical self-hosted proof can be obtained without
amplifying the current runner queue.
