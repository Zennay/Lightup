# Scope authorization: no transitive delegation (offline acceptance contract)

Status: proposed acceptance boundary for M7/ST5; **not production enforcement**.

## Invariant

Authorization grants are not transferable: a client, worker, subagent, service account, queue lease, correlation ID, finding, or delegated job cannot mint authority for another principal, tenant, target, capability, risk level or timeframe. A parent decision is evidence of its own evaluation only, not a portable bearer capability. A descendant must be independently checked against trusted issuer-held active authorization **at admission and immediately before dispatch**, including retries.

## Negative acceptance matrix

1. Parent worker has valid grant; child worker lacks a trusted principal binding: deny child.
2. Child copies parent decision or serialized approval: deny without issuer-owned revalidation.
3. Tenant A parent schedules tenant B child: deny.
4. Child adds an asset, wildcard, capability or risk level absent in the trusted grant: deny.
5. Child narrows asset/capability but omits live grant lookup: deny; narrowing alone is not proof.
6. A parent grant expires or is revoked after enqueue: deny child dispatch and retry.
7. Descendant changes approved engagement or approval revision: deny pending fresh approval.
8. Valid parent with a nonempty job/correlation ID but no scoped child identity: deny.
9. Scope-check service/store/audit dependencies unavailable: deny safely; do not fall back to inherited authority.
10. Positive control: eligible child identity and requested bounds are independently validated against an active trusted issuer-owned grant at dispatch; only then may the owning runtime consider it eligible, subject to all other gates.

## Production-owner handoff

- #107 owns runtime checks and orchestration; #992 owns approval provenance; #983/#989 own revocation behavior.
- Use immutable issuer-origin record identifiers, explicit principal/tenant/engagement bindings, current authorization epoch and bounded scope; never infer a grant from an LLM output or ancestor task.
- Require a negative end-to-end test for each applicable case, plus exact-head hosted and permanent VPS proof and human review before promotion.
- This reference contains no tokens, issued grants, target addresses, scan commands or activation. Documentation/tests are **not** authorization.
