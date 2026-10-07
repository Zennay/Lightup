# Canonical grant scope-object contract

This acceptance slice pins the runtime object boundary at durable client-grant
issuance above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Invariant

`DomainStore.record_authorization_grant()` must accept authorization scope only
from an exact canonical `ScopeDefinition` object.

Type annotations alone are insufficient because authorization fields are read
multiple times before and during persistence. A duck-typed or polymorphic
object can expose different values across those reads. In particular,
`max_risk` is validated and later serialized in separate accesses; a
stateful object can therefore present `STANDARD` to the guard and
`DESTRUCTIVE_LAB_ONLY` to persistence.

The boundary must therefore reject before writing when:

- the scope is merely structurally equivalent to `ScopeDefinition`;
- the scope is a `ScopeDefinition` subclass rather than the exact trusted
  object type;
- repeated reads could substitute a different risk or other authority field.

Canonical exact `ScopeDefinition` issuance remains unchanged.

## Acceptance proof

`tests/test_scope_authorization_grant_scope_object_types.py` provides:

- an exact `ScopeDefinition` green control;
- a structurally equivalent duck-scope expected rejection;
- a `ScopeDefinition` subclass expected rejection;
- an oscillating-risk scope that presents `STANDARD` for validation and then
  `DESTRUCTIVE_LAB_ONLY` on the later serialization read;
- durable row-count checks proving rejection happens before persistence;
- a persisted-risk assertion that explicitly catches destructive authority if
  the TOCTOU object is accepted.

Against exact #554 source, the non-canonical cases are intentionally expected
RED until the domain authorization owner adds the narrow object-type guard.

## Separation from existing owners

- #119 owns scalar `RiskLevel` type confusion; this contract keeps every
  exposed risk value a real `RiskLevel` member and instead attacks the outer
  scope object boundary.
- #376 owns durable asset-entry validation.
- #177 owns assessment-request to grant provenance.
- #554/#639 own execution-time durable revalidation.
- execution asset/capability/lineage typing remains in its existing runtime
  acceptance lanes.

## Collision boundary

Tests/documentation only. No change to `src/lightup/domain.py`,
`src/lightup/engagements.py`, execution policy/orchestration, or target-capable
source.

## Safety

Temporary SQLite and in-process grant construction only. No DNS/network I/O,
target interaction, scanning, exploit behavior, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
