# Tenant-bound scope authorization: reviewer handoff checklist

**Status:** proposed offline review contract, not evidence that enforcement exists.  
**Phase:** M7/ST5 fail-closed hardening.  
**Boundary:** no change to production authorization, execution or active target capability.

## Mandatory review invariants

Before any authorization-related implementation may be promoted, its owner must demonstrate:

1. **Issuer lineage:** the permission used at dispatch is tied to a trusted, durable grant issued for the same tenant and engagement. Object equality, a copied grant ID, or user-supplied `client_id` alone are not issuer proof.
2. **Target binding:** the requested asset and capability are contained in the intersection of the original approved snapshot and the *current* narrower live grant, with exclusions applied before any dispatch.
3. **Human approval:** an approval belongs to that exact tenant, engagement, grant revision, risk envelope and intended assessment mode. Approval for one tenant/engagement cannot be reused for another, even with an equal string reference.
4. **Temporal validity:** both snapshot and live grant are valid at each dispatch boundary; a reapproval cannot resurrect work from an older grant revision.
5. **Revocation:** expiry, deactivation, revision changes or scope narrowing deny queue pickup, retries and subsequent steps. In-flight cancellation must be explicitly tested by the executor owner rather than inferred from a reference model.
6. **Audit failure:** if the audit/provenance sink cannot persist an authoritative decision, target-capable work fails closed; audit labels must not be treated as proof of authorization.
7. **Risk separation:** analysis-only and passive prospect records cannot be upgraded to target-active permission through mode coercion, risk-slider values, stale session data or role confusion.
8. **Cross-tenant isolation:** corrupt or mismatched persisted `client_id` / `engagement_id` / `grant_id` combinations are denied on reads *and* at execution, without mutating data during a denial.

## Required negative evidence

For each invariant record a regression with a canonical positive control and a denied negative case, including:

- the same grant ID under a different tenant or engagement;
- stale approved revision following reapproval or revocation;
- narrowed capability/asset set while a request is queued;
- forged or type-confused identities and approval booleans;
- an invalid or absent audit persistence outcome;
- a running multi-step task losing authorization between steps.

Each case must assert **zero target-capable invocations** on denial. Expected-RED tests are useful findings, never success evidence.

## Promotion receipt

Record the exact implementation commit SHA, owning PR, explicit human review, and distinct successful hosted and permanent `vps-bb300bba` test runs for that same SHA. Record relevant focused test counts and failures. A successful review of this document does not authorize assessments; deployment and activation require their own explicit approvals.

## Ownership / non-overlap

This document is a read-only, independent checklist. PR #107 owns `ToolExecutor` production changes. PRs #982, #983, #989 and #992 own release receipts, revocation fixtures/reference models and approval provenance respectively. Existing tenant-lineage issues #808/#829 own their specific domain read regressions. Do not cherry-pick this document as an implementation or substitute it for the owners' tests.

**Safety:** offline review only; no DNS, network requests, real targets, scans, handler calls, credentials, active dispatch, deployment or authorization widening.
