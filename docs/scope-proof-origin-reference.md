# Authorization proof-origin binding — offline acceptance reference

Status: **proposed reference only**, not an active authorization source.

## Threat boundary

Findings, uploaded reports, simulated lab evidence, scanner responses and AI
output may contain strings that *look* like an authorization reference. Those
strings are evidence, not grants. A consumer must not treat a copied approval
flag, grant ID, or issuer field as authenticated authority.

## Proposed acceptance

A real authorization decision must re-resolve the current, independently
authenticated authorization register on every admission and dispatch step.
The issuer-controlled grant must bind exact tenant, request, issuer, grant
reference, current revision, permitted assets/capabilities, risk and validity
window. Revocation wins over cached or copied evidence. Client-supplied
origin labels are not trusted proof of where a record came from.

The bundled stdlib test is deliberately a small **offline model**: it proves
that a forged origin label, cross-tenant/request/issuer/reference swap, truthy
approval, polymorphic input, ambiguous edge whitespace or ASCII control characters\ninside an identity is denied by the stated reference predicate.
It does **not** authenticate the provenance of the string
`trusted_authorization_register`; only integration with a trusted backend
can establish that. The positive fixture is therefore conditional, not a
production permission. Do not use `eligible` for real target execution.

## Ownership and release

No production implementation, live grant issuance, target adapter, network
interaction, scan, deployment or widening of permission in this branch.
Production executor ownership stays with the active scope source owner (PR
#107). Acceptance requires that owner to integrate equivalent checks with
trusted issuer lineage, plus exact-head hosted and permanent-VPS green proof
and human review before promotion.
