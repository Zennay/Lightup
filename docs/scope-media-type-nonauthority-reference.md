# Scope authorization: media-type and parser metadata are not authority

This is an **offline, synthetic, non-production reference contract**.

HTTP `Content-Type`, declared charset, a successful deserialization, a correctly
computed content digest, and a vendor MIME suffix are metadata about an
evidence carrier. **None can issue, revive, transfer or widen an authorization
grant.** Treat body content from scanners, proxy caches, reports, uploads or
client APIs as untrusted even when the media type looks official.

## Mandatory integration boundary

Before *each* active dispatch, the production owner must independently resolve
the current grant from an authenticated issuer-owned record, verify consent
and approval provenance, revocation, request revision, tenant, exact capability,
scope/target, time window, risk tier and activation policy. A cached or parsed
evidence body is never a substitute. Any invalid/missing binding denies.

The conditional `allowed` predicate in the accompanying test is not a
production gate. Its synthetic `issuer_verified=True` flag cannot verify
a signature or authorization provenance. Even its positive results **do not
permit real-target activity**. Parsing rules for accepted media types and
character encodings must be separately enforced by the production owner;
transport fields are intentionally ignored by this reference to demonstrate
their inability to influence permission.

## Review/validation

Run `python -m unittest discover -s tests -p 'test_scope_media_type_nonauthority_reference.py' -v`
with Python 3.11 and 3.14, then permanent VPS CI at the **exact PR head**.
The expanded fixture now includes 17 test methods, with exact dispatch/grant revision typing, malformed matching identities in every identity field, and non-mutation checks. Control-byte fixtures use Python escape sequences that evaluate to actual control bytes, not literal backslash characters.\nRemain draft until green proof and review by the source owner of PR #107.
No source executor edits, grant issuance, targets, network, DNS, scanning,
credentials, capability dispatch or deployment are included.
