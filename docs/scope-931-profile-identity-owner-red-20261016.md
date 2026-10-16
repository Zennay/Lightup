# #931 — canonical passive-prospect identity (owner-source RED acceptance)

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · non-authorizing.
**Pinned original source owner:** draft [#175](https://github.com/Zennay/Lightup/pull/175) at immutable `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.
**Issue:** [#931](https://github.com/Zennay/Lightup/issues/931).
**New isolated test:** `tests/test_scope_931_profile_identity_owner_red_20261016.py`.
All names, sources and signals are fictional and remain entirely in process. No DNS,
network I/O, external target, customer record, grant, scan, or handler invocation.

## Gap / installed-source witness

Owner-source `ProspectProfile` is a mutable dataclass with ordinary annotated
`prospect_id` and `organization_name` fields. Python dataclass type annotations
do not validate runtime inputs. On this exact head, `ProspectProfile(None, ...)`,
`ProspectProfile("", ...)`, etc. currently construct an object. A passive,
public-only signal can then be attached to an ambiguously identified profile.
Existing correct `ProspectSignal.public_source` and
`requires_target_interaction` boolean gates **do not** validate profile identity.

## Contract and acceptance evidence

- Four ordinary installed-source PASS checks: exact string identity preserved,
  passive canonical signal admitted, nonpublic/interactive/type-confused signal
  rejected without append, and profile identity creates no target permit.
- Twelve deliberately `@expectedFailure` **OPEN SOURCE RED** checks:
  null, numeric, subclass, blank, whitespace identities for the prospect;
  corresponding organization cases; object with coercion hooks; and
  malformed profile rejected *before* constructor signal admission.
- One strict independent replay oracle asserts **all 12 real expected failures**,
  no skips/errors/unexpected successes. When the source owner fixes the bug, it
  intentionally fails rather than silently treating an unexpected pass as safety.
- This test does not assert a production fix, release permission, approval, or
  authentication/authorization. Hosted test success with expected REDs is not a
  green security posture.

## Source-owner repair handoff (NOT implemented here)

The only production owner is PR #175 / `src/lightup/discovery.py`; do not alter
their source or branch from this child. They should validate with exact built-in
`type(value) is str` and nonempty `value.strip()` on **both** identity fields
before accepting a profile or its initial signals, without trimming, normalizing
or evaluating polymorphic caller hooks. Prefer `ValueError` for malformed text
and preserve canonical strings byte-for-byte. Keep `ProspectSignal` exact-bool
fail-closed behavior; do not widen public/prospect admission. Independently
review whether identity can mutate after construction (#929), then enforce
identity validity at any relevant mutation/admission boundary.

After source correction, intentionally RED tests must be converted to ordinary
PASS assertions *in a source-owner reviewed change* and accompanied by a strict
latest-head CI matrix. A successful isolated child does not merge the owner fix.

## Required external gates

1. Independently reviewed owner-source #175 fix and #929 immutability composition.
2. Full hosted Python 3.11/3.14 and genuine permanently registered self-hosted
   VPS CI on the **exact final SHA**. Queued jobs do not count as evidence.
3. Security/privacy and legal permission review, explicit human release.
4. No real target access without actual client authority, current scope,
   revocation checks, separate operator permission and appropriate risk gate.

**NO MERGE / DEPLOY / REAL GRANTS / TARGET SCANS / ACTIVE SECURITY ACTIONS.**
