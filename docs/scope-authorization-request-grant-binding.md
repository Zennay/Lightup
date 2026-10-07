# Assessment-request to authorization-grant binding

Issue: #177  
Acceptance base: PR #142 exact head `f6214a1dc3b2a86780e1b1d04d8e0803947e61ba`

## Purpose

The product contract requires reviewed client intent before target-active authority can exist. A structurally valid authorization grant must therefore not be mintable independently of an approved assessment request.

This branch is an **acceptance-only reservation**. It does not change `DomainStore`, the authorization schema, or any target-capable path while the domain owner stack remains active.

## Required invariant

Before a client-target authorization grant can be persisted, durable state must prove an assessment request that:

- belongs to the same client;
- has status `APPROVED`;
- requests `AUTHORIZED_ASSESSMENT`;
- covers every granted asset after the canonical identity rules owned by the scope/domain stack;
- approves a risk level at least as high as the grant maximum.

The grant must retain immutable provenance to the approved request (for example the request ID on the grant or an equivalent binding record) so later execution-time revalidation can prove the lineage again. The implementation shape remains owned by the composed domain stack.

Pending, rejected, missing, wrong-client, wrong-mode, asset-widening, or risk-widening request state must never mint target-active authority.

## Acceptance cases

`tests/test_scope_authorization_request_grant_binding.py` provides:

- one positive control for a matching approved request;
- expected-RED denial when no approved request exists;
- expected-RED denial for a pending request;
- expected-RED denial for a rejected request;
- expected-RED denial when the grant widens the approved asset set;
- expected-RED denial when the grant exceeds approved risk.

The expected REDs prove the current domain bypass without modifying the source-owner implementation.

## Collision and sequencing

Issue #177 explicitly defers production changes while `domain.py` / `tests/test_domain.py` are owned by #132, #135, #138, #142 and #146, with scope canonicalization in #153. This branch therefore adds only a new test module and this document. It intentionally has no PR/CI slot until the owner chain is ready to absorb the invariant.

## Safety

Authorization provenance narrowing only. No target interaction, scanning, exploit behavior, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
