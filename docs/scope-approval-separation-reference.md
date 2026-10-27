# Scope approval separation-of-duties — offline reference only

Status: M7/ST5 **proposed acceptance reference**, not a production permission check.

A single person must not both request and independently approve the *same*
tenant-scoped, revision-pinned active-test authorization. The offline reference
requires exact requester/approver identity inequality, a matching tenant,
request identifier, request revision, canonical field types, and an explicit
active boolean. Changing the requester, tenant, or revision invalidates the
old approval. Truthy substitutes, subclasses, and identity coercion are denied.

The positive reference result means **conditionally eligible only**.
String comparison alone cannot establish authenticated actor identity,
distinct real humans, issuer ownership, signer lineage, revocation status,
current consent, authorized assets/capabilities, risk ceilings, expiry, or
a valid live grant. Production admission and every dispatch MUST validate
those controls using trusted state; actor aliases or multiple accounts owned
by one person require an explicit organizational identity control. Failing
audit writes, missing records, or changes after approval must deny, never
silently reapprove.

## Non-overlap and promotion

This branch adds only this document and an isolated stdlib unittest reference.
It does not modify the production executor in PR #107, policy, grant issuance,
approval provenance in PR #992, revocation in #983/#989, or release receipts
in #982. Owner integration should add real-domain tests and prove no
authority widening at admission, queue retry, and dispatch. Keep draft until
exact-head hosted and permanent VPS evidence plus production-owner review.
No network, DNS, active target interaction, scans, grants, or deployments.
