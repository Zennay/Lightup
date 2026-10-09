# Authorization event sequence continuity — offline reference contract

This is a **non-authorizing reference** for detecting missing or reordered events in an already authenticated, issuer-owned authorization ledger. It is not a replacement for the production executor gate owned by PR #107.

## Proposed fail-closed requirement

Before consuming any event-derived grant state, resolve tenant and grant from trusted server-side context, obtain the ledger's authenticated checkpoint and compare every subsequent event's strictly increasing contiguous integer sequence. Reject missing events, duplicates, reordering, cross-tenant/grant substitutions, unknown event kinds, unexpected types (including bool as integer), polymorphic event types, and empty results.

Do not infer permission from a successful continuity check. An attacker can forge a perfectly contiguous list. Production must separately verify issuer provenance, tamper-evident storage/transactional append, authorization revision, independent approval, scope/risk, live expiry and revocation, and atomic dispatch-time revalidation. Missing history, unavailable ledger and unresolved checkpoint must fail closed; this reference bounds sequence integers to signed 64-bit nonnegative values, event batches to 1–1024 elements, and ASCII token identities to 1–128 characters with only letters, digits, hyphen and underscore. The production owner must explicitly choose matching deployed limits and enforce checkpoint arithmetic atomically.

This reference intentionally checks shape and continuity only. It does **not** implement persistence, cryptographic authentication, signatures, capability execution, targets, DNS, network, scanning, or activation. Authorization cannot be inferred from the `issued` or `approved` event names.

## Test

`python -m unittest discover -s tests -p 'test_scope_authorization_event_sequence_reference.py' -v`

## Release gate

Draft until owner review, exact-head Python 3.11/3.14 hosted checks and canonical permanent self-hosted VPS CI prove this change. Integration with the source owner's ledger and executor requires separate real implementation and validation.
