# Scope authorization: canonical assessment-request asset identities

Issue: #654  
Domain source owner: active scope-authorization chain / draft #554 parent snapshot  
Exact acceptance parent: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

Assessment requests are authorization provenance. The planned #177 grant-binding invariant will rely on the approved request's asset set when deciding whether a grant is a subset of human-approved scope.

Current intake builds that set with:

```python
assets = tuple(a.strip() for a in requested_assets if a.strip())
```

For every kept item, `strip()` is called once to decide whether the item survives and again to choose the value that is persisted. Because item typing is annotation-only, a polymorphic string can make those reads disagree.

The request can therefore persist asset B after validation observed non-blank asset A.

## Contract

Every requested-asset item must be an exact built-in `str`.

For an accepted exact string:

1. take one stripped local snapshot;
2. apply the existing empty-entry policy to that snapshot;
3. persist exactly that snapshot.

A string subclass or duck object must fail before calling overridable normalization methods and before writing an `assessment_requests` row.

This slice preserves current handling for exact whitespace-only entries: they may be ignored when at least one canonical non-empty requested asset remains. It does not broaden the request policy.

## Expected RED on the parent

The regression supplies a `str` subclass whose first `strip()` returns `approved-at-filter.example` and whose second returns `different-at-persistence.example`.

Current code calls both and persists the second value. The acceptance contract requires a controlled rejection before either polymorphic call.

A second RED case proves that even a subclass returning matching text is not a canonical identity object.

## Independence

- #177 owns approved request → durable grant binding and subset semantics.
- #376/#648/#650 cover grant-scope integrity after the request boundary.
- `chatgpt/scope-authorization-assessment-plan-integrity-20261006` modifies orchestrator planning, not domain request intake.

#654 only fixes what identity becomes eligible to enter the authorization provenance record.

## Collision and safety

This branch adds only:

- `tests/test_scope_authorization_request_asset_identity.py`;
- `docs/scope-authorization-request-asset-identity.md`.

There are **0 production/source changes**. No domain/web/orchestrator source is modified.

The proof uses temporary SQLite only. It performs no DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
