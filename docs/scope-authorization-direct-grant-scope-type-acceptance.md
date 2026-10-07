# Direct durable-grant scope object acceptance

Tracked by #740.

## Boundary

`ExecutionPolicy.decide()` consumes the scope stored on an in-memory `AuthorizationGrant`. At this boundary, exact scope identity matters: methods on a polymorphic or duck-typed object must not be able to manufacture asset/capability authority.

## Required behavior

Canonical controls:

- an exact `ScopeDefinition` authorizes its exact asset/capability pair;
- the same exact scope denies a foreign asset.

Hardening acceptance:

- a `ScopeDefinition` subclass that overrides `allows_asset()` and `allows_capability()` to return true must still be denied;
- a structurally compatible duck-typed scope with allow-all methods must still be denied;
- rejection leaves the grant's scope object unchanged.

Current PR #100 policy source is expected RED for exactly the two non-canonical scope-object methods because it does not require `type(grant.scope) is ScopeDefinition` before reading the scope.

## Non-overlap

- #646 owns exact scope-object integrity at issuance/persistence;
- #575/#576 own runtime request asset/capability identity typing;
- #106 owns canonical live durable re-resolution before handler dispatch;
- this contract is limited to the direct in-memory grant object consumed by `ExecutionPolicy`.

The branch is pinned to PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f` and changes tests/docs only.

## Safety

No target/network activity or handler invocation occurs. This is deterministic in-memory authorization narrowing only.
