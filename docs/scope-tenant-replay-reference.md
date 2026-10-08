# Tenant replay denial — offline reference contract

This isolated acceptance fixture defines six cases for **tenant-bound, revision-bound** authorization snapshots. It is a reference model only, not a security gate: production must obtain its identity and grant from a trusted issuer, perform a live resolution immediately before each execution step, and fail closed if that resolution is absent, revoked, expired, cross-tenant or changed.

## Reference invariants

- Exact canonical tenant identity must match; case-insensitive matching or coercion cannot mint rights.
- A foreign-tenant grant remains denied even if its revision is the same or newer.
- An inactive grant is denied even with matching tenant and revision.
- A replaced revision is denied until a separately approved snapshot exists.
- Boolean/number/string type confusion cannot promote active status or revision.
- Reference fixture's positive case means only conditional eligibility, **never permission to dispatch**.

## Ownership and promotion

No production code is changed. The executor implementation belongs to PR #107; human approval provenance belongs to #992; revocation belongs to #983/#989; release receipt verification belongs to #982. Integrate only after their owners verify trusted issuer lineage, per-step revalidation, asynchronous cancellation and exact-head hosted/permanent VPS CI. This pack does not test those integration properties.

Run: `python -m unittest discover -s tests -p test_scope_tenant_replay_reference.py -v`

Offline only; no DNS, sockets, targets, scanning, authorization minting or executable capability dispatch.

## Adversarial identity fixtures

The dedicated regressions also reject case-folded tenant aliases, leading/trailing whitespace, embedded control characters, visually confusable Unicode substitutions and `str` subclasses. The reference check leaves its input mapping unchanged. These checks are deliberately local and must not be interpreted as a canonical identity normalization implementation. Production needs an issuer-controlled tenant identifier rather than trusting caller-supplied spelling.
