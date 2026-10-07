# ScopeDefinition exact collection and entry types

Issue: #775  
Parent contract: #648  
Pinned parent: PR #554 exact head `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

A frozen `ScopeDefinition` is authorization state. Tuple annotations do not make caller-supplied containers or entries canonical.

Construction must fail closed unless:

- `type(assets) is tuple`;
- `type(excluded_assets) is tuple`;
- `type(allowed_capabilities) is tuple`;
- every collection entry has `type(entry) is str`.

Validation must happen when the scope object is created, before `allows_asset()`, `allows_capability()`, grant issuance, or policy evaluation can observe caller-controlled protocol behavior.

## Acceptance matrix

Green control:

- exact built-in tuples containing exact built-in strings retain current allow/exclude/capability semantics.

Expected RED on the pinned #554 source:

- an `assets` tuple subclass that stores a foreign host but overrides iteration;
- an `excluded_assets` tuple subclass that stores a real exclusion but iterates empty;
- an `allowed_capabilities` tuple subclass that returns true from `__contains__`;
- an asset `str` subclass that overrides canonicalization;
- an exclusion `str` subclass that overrides canonicalization;
- a capability `str` subclass that equality/hash-spoofs another capability.

Current source accepts all six malformed constructions because `ScopeDefinition` has no constructor-time exact-type invariant.

## Non-overlap

- #648 owns mutable-list snapshot/isolation semantics. #775 is its exact-type child.
- #376 owns asset-entry validation at durable grant issuance.
- #650 owns capability identity validation at durable grant issuance.
- #639 owns already-persisted scope entry validation.
- #575/#576 own runtime request asset/capability identity.
- #730 owns the separate legacy `Authorization.assets` exact-type boundary.
- #740 owns only the outer direct `grant.scope` object type.

## Collision boundary

Tests/docs only. No production source is modified; the active ScopeDefinition/source owners retain repair ownership.

## Safety

Pure in-memory authorization narrowing acceptance. No DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
