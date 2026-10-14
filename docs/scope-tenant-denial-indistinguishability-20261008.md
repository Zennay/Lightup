# Tenant denial indistinguishability — offline acceptance reference

## Objective
A caller must not learn whether a tenant, grant, reviewer, account or scope exists merely by submitting an unauthorized request. Unknown tenant, foreign tenant, inactive grant and out-of-scope requests must have a consistent public denial shape. Internal structured reasons can remain in access-controlled audit records, never in the caller response.

## Scope and limits
The companion Python unittest file is a **pure reference model**, not an integration test of a LightUp endpoint, real authorization decision, audit system or timing side channel. Its positive reference case is a synthetic truth table and **does not permit execution**. No production source, network, DNS, target, scan, runtime capability or deployment is changed.

## Required production-owner integration
- Authenticate the caller before tenant-scoped resource resolution; never expose existence-specific error text to an unauthenticated or unauthorized principal.
- Use a stable public 403 payload for nonexistent tenant, inaccessible tenant, revoked/expired grant and denied asset/capability. Choose exact HTTP semantics in the owning API, including whether intentionally concealed resources return 404, then enforce one indistinguishable policy for that route.
- Reject truthy non-boolean grant and scope flags; require trusted issuer provenance, live revocation checks, explicit human approval and exact tenant/revision binding independently of this reference.
- Keep private identifiers and rich denial reasons in tenant-partitioned, access-controlled audit records, with data minimization.
- Add real endpoint tests comparing body, status, headers, response size and caching for denial variants. Timing and rate-limit enumeration risks require separate integration/security review.
- On every retry, recheck the current authorization snapshot; do not cache an affirmative result from this reference function.

## Offline check
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_tenant_denial_indistinguishability_20261008.py' -v`

## Promotion
Remain draft until the production authorization owner (currently PR #107) reviews expected response semantics and integrates an enforcement test; exact-head hosted CI and permanent VPS proof must pass. No claim of green CI, runtime safety or authorization is made here.
