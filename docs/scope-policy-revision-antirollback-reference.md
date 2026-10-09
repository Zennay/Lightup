# Scope authorization — policy revision rollback offline reference

**Status:** proposed ST5 fail-closed reference only; neither production permission nor evidence of executor integration.

A queued run must not gain permission because the *current* issuer-owned policy record has rolled back behind the revision captured by the run. At execution and every retry, compare exact tenant and grant identities and exact nonnegative integer revisions. A lower current revision, revocation, malformed identity or malformed active flag denies continuation. Same/newer revision is **only a necessary condition**; a newer revision can still remove scope, change risk, revoke approval or expire, so the production executor must independently check those bounds.

## Trust boundary

The offline model in `tests/test_scope_policy_revision_antirollback_reference.py` deliberately does **not** fetch an issuer-owned policy register or establish authenticated lineage. Caller-supplied "current" records cannot authorize a real capability. The production owner must load issuer-authenticated state at admission and immediately before dispatch; stale caches, mismatched policy families, and missing records deny. Revision must be monotonically assigned by trusted persistence with concurrency protection; never trust a user-provided number.

## Acceptance matrix

- Same revision and newer revision only pass this **necessary** reference predicate.
- Lower revision, disabled current record, tenant/grant swap, invalid type, negative/boolean revision and dataclass subclass deny.
- Malformed identities deny, including embedded ASCII controls, Unicode direction/line separators, path separators, overlong inputs and malformed *saved* identities. The reference uses an illustrative conservative 1–128-character ASCII identity grammar; production issuer-owned canonical identity policy must be specified independently. Offline tests never open sockets or dispatch tools.
- Production acceptance must separately prove atomic read/revalidate/dispatch behavior, revocation visibility, policy lineage, expiry, capability/risk monotonicity and zero effects on denial.

## Coordination and evidence

This contribution adds only a standalone Python stdlib unittest and this document. Do not modify source files owned by executor PR #107, approval provenance #992 or revocation #983/#989. No target contacts, network scanning, grant issuance, activation, permission widening or deployment. Keep draft until exact-head Python 3.11/3.14 hosted checks, canonical permanent VPS checks and source-owner review; previous-head checks are not proof.
