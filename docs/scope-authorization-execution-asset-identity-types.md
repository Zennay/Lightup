# TARGET_ACTIVE execution asset identity type contract

This acceptance slice pins a narrow authorization-boundary invariant above exact
#554 head `4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Why this matters

A target-active `ToolCall.asset` is caller-controlled runtime data. The current
execution path passes it into `ScopeDefinition.allows_asset()` after live
authorization revalidation, but it does not first require the asset identity to
be an exact built-in `str`.

`ScopeDefinition._canonical_asset()` calls `.strip()`, `.rstrip()`, and
`.lower()`. Each operation can be overridden by a `str` subclass. A foreign
underlying asset can therefore retain different stored text while returning the
allowlisted hostname from any step in the canonicalization chain.

The durable grant itself stays canonical in this contract. The gap is only the
untrusted runtime execution asset crossing a trusted authorization comparison.

## Required behavior

TARGET_ACTIVE execution must preserve all of these properties:

- an exact built-in allowlisted asset remains executable;
- an ordinary foreign exact string remains denied;
- a `str` subclass carrying a foreign underlying asset cannot override
  `.strip()`, `.rstrip()`, or `.lower()` to inherit allowlisted authority;
- a `str` subclass is denied even when its underlying text exactly equals the
  allowlisted asset;
- every denied case is rejected before handler dispatch;
- every denied case is state-atomic across `runs`, `capability_leases`, and
  `evidence`;
- durable authorization state is neither normalized nor rewritten.

The dedicated regression uses the real `DomainStore` execution resolver, the
real `ToolExecutor`, temporary SQLite state, and an inert target-active handler.
It therefore tests the composed live-resolver -> execution-policy -> dispatch
boundary rather than only calling `ScopeDefinition` in isolation.

## Expected state

`tests/test_scope_authorization_execution_asset_identity_types.py` contains:

- one canonical exact-string green control;
- one ordinary foreign-string green denial control;
- three expected-RED foreign-asset canonicalization spoof cases, one for each
  overridable normalization step;
- one expected-RED matching-text subclass case.

Against the pinned #554 source, the ordinary foreign asset is denied. Each
canonicalization-spoof case can currently cross scope because the subclass
returns `allowed.test` during the normalization chain. The matching-text
subclass also crosses because the boundary has no exact-type guard.

The intended repair is authorization narrowing only: require a canonical
built-in string asset before any polymorphic string behavior can participate in
scope canonicalization.

## Collision boundary

Tests and documentation only. This branch does not modify
`src/lightup/execution_policy.py`, `src/lightup/ai/orchestration.py`,
`src/lightup/engagements.py`, domain persistence, or existing tests.

This is distinct from:

- #567 client/engagement execution-lineage identity typing;
- #376 durable grant asset-entry validation;
- #151/#117 durable asset canonicalization ownership;
- #497 legacy `Target` value/type acceptance.

## Queue policy

Keep this acceptance branch PR-free initially while existing scope-authorization
proof work occupies the permanent self-hosted lane. No duplicate/retrigger is
needed merely to materialize this expected-RED contract.

## Safety

Offline/in-process authorization narrowing proof only. No DNS/network I/O,
target interaction, scanning, exploit behavior, remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
