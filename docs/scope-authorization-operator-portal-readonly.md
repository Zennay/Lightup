# Scope authorization: operator portal write boundary

Issue: #673

## Contract

The client portal has two different authority surfaces:

- an operator may view a client portal for support/review purposes;
- a client assessment request must originate from a real signed-in client identity bound to that client.

Operator read access must therefore not imply client write authority.

The POST route that creates a client assessment request must reject an operator session before durable mutation. It must not synthesize a client role from the operator identity for this action.

## Why this matters

The persisted assessment request records `requested_by` and is later reviewed by an operator. If the same operator can enter the client portal, submit the request through a synthetic client context and then review it as an operator, request provenance no longer represents the client → operator review boundary described by the product workflow.

This acceptance slice intentionally does not decide later request → grant semantics. Issue #177 owns that domain binding. It only pins the earlier web authorization boundary so an operator cannot manufacture the client-originating request through the client portal.

## Acceptance

- operator GET `/portal/<client_id>` remains allowed;
- operator POST `/portal/<client_id>/requests` returns `403 Forbidden`;
- rejected operator POST leaves assessment-request storage unchanged;
- a matching real client session can still submit;
- the persisted `requested_by` for that successful client request is the client's real user ID;
- cross-tenant, CSRF and operator decision behavior stay under their existing owners.

## Current expected state

Against current `main`, the operator-write rejection regression is expected RED because the shared `portal` access class admits operators and `_portal_context()` creates a synthetic `CLIENT_ADMIN` context for the selected client.

The source repair should remain with the web authorization owner after active web work is composed. This branch does not modify production source.

## Collision boundary

This branch adds only:

- `tests/test_scope_authorization_operator_portal_readonly.py`;
- this contract document.

It does not modify:

- `src/lightup/webapp/app.py` (#182 web authorization input owner);
- `src/lightup/domain.py` or `AccessContext` (#670 and durable authorization owners);
- assessment request → grant binding (#177);
- scope, activation, execution policy, workers, evidence-remediation, deployment, verdict or attack-path state.

## Safety

Offline/in-memory authorization and provenance proof only. No DNS/network target interaction, scanning, exploit behavior, tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
