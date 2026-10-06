# Scope authorization: mutable policy snapshot acceptance

Issue: #294

This tests/docs-only contract is based on exact current `main`
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Boundary

`ScopePolicy` is frozen, but that does not make caller-owned mutable
collections immutable. Runtime list/set inputs must be validated and snapshotted
at policy construction so an already-created authorization policy cannot change
when the caller later mutates those containers.

The acceptance proves:

- mutable `explicit_hosts` input becomes an immutable `frozenset`;
- later mutation of the caller-owned host set cannot widen scope;
- mutable `explicit_networks` input becomes an immutable tuple;
- later mutation of the caller-owned network list cannot widen scope;
- canonical immutable inputs keep their existing explicit-host/network behavior.

## Expected RED on current main

Type annotations do not coerce runtime values. A caller can pass a mutable set
or list into the frozen dataclass, and `ScopePolicy.decide()` reads that same
object later. Mutating the caller container therefore changes decisions of the
already-created policy.

## Collision boundary

This branch adds only:

- `tests/test_scope_policy_mutable_snapshot_acceptance.py`;
- this document.

It does not modify `src/lightup/scope.py`, the existing policy-monotonicity
branch, #290/#292/#296/#297 files, models, activation, execution policy,
domain/state, webapp, or target-capable code.

## Safety

Pure in-memory authorization-configuration integrity proof. No DNS, sockets,
HTTP, target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
