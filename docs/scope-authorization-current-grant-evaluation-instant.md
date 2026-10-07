# Scope authorization — current-grant evaluation instant

Issue #890 pins the optional evaluation-time boundary on
`DomainStore.get_current_grant()` above exact source owner #107.

## Contract

`None` is the only omission sentinel for `now`.

- omitted / `now=None` may evaluate at current UTC time;
- an exact timezone-aware `datetime` remains valid;
- any explicitly supplied falsy non-datetime value fails closed;
- malformed input is never silently replaced with wall-clock time;
- rejection is read-only and does not mutate grant state.

The regression covers `False`, integer/float zero, empty text, empty bytes and an
empty list.

## Relationship to direct grant-time validation

#734/#735 own the evaluation input accepted by
`AuthorizationGrant.is_current(now=...)`. This issue is intentionally narrower:
`get_current_grant()` currently consumes falsy malformed input with
`now = now or utcnow()` before the direct grant method can see it.

## Expected state on the pinned parent

Pinned parent: exact PR #107 head
`c37ee27d922a7dd400eee1db39268f4a6269e431`.

The omission and exact-aware-datetime controls are expected GREEN. Every
explicit falsy non-datetime case is intentionally expected RED because the
selector currently substitutes `utcnow()` and can return a live grant.

## Safety and collision boundary

Tests and documentation only. No #107 production source is modified, and
#734/#735 retain direct `AuthorizationGrant.is_current` ownership.

The regression uses temporary SQLite only and performs no DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
