# Immutable ScopeDefinition input contract

This acceptance slice pins the collection-ownership boundary of durable grant
scope objects above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Invariant

`ScopeDefinition` is frozen, but Python's frozen dataclass semantics do not
make caller-owned mutable field values immutable. The tuple annotations on
`assets`, `excluded_assets`, and `allowed_capabilities` are not runtime
enforcement.

If a caller supplies lists, `record_authorization_grant()` persists a JSON
snapshot while the returned `AuthorizationGrant` retains the original
`ScopeDefinition`. Later mutation can therefore make the already-issued
in-memory grant disagree with its durable scope:

- appending an asset can widen `allows_asset()`;
- clearing an exclusion can remove a denial;
- appending a capability can widen `allows_capability()`.

The trusted scope object must either snapshot collection inputs into immutable
tuples at construction or reject mutable/non-tuple collection inputs. External
mutation must never change authorization decisions after construction or
issuance.

## Acceptance proof

`tests/test_scope_authorization_scope_definition_mutable_inputs.py` provides:

- a canonical tuple-based green control;
- caller-owned asset-list mutation;
- caller-owned exclusion-list mutation;
- caller-owned capability-list mutation;
- durable-row snapshots proving external mutation does not change the persisted
  JSON snapshot.

The mutable-input tests accept either safe implementation strategy: immediate
constructor rejection, or successful construction with an immutable internal
snapshot.

Against exact #554 source, accepted list inputs remain aliased and the three
mutation cases are intentionally expected RED.

## Separation from existing owners

- #300 covers mutable asset scope on legacy `models.Authorization`.
- #294 covers mutable public `ScopePolicy` configuration.
- #370 covers order/duplicate invariance, not caller-owned mutation.
- #376 covers durable asset-entry validation.
- #646 covers the outer object type at grant issuance; this slice deliberately
  uses the exact `ScopeDefinition` type.
- #554 ensures TARGET_ACTIVE dispatch re-resolves durable grants, but the grant
  object itself must still remain immutable once issued.

## Collision boundary

Tests/documentation only. No changes to `src/lightup/engagements.py`,
`src/lightup/domain.py`, execution policy/orchestration, evidence remediation,
or target-capable source.

## Safety

In-memory authorization-scope checks plus temporary SQLite only. No DNS/network
I/O, target interaction, scanning, exploit behavior, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
