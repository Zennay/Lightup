# Evidence tombstone transition — offline reference contract

Status: **proposal / acceptance reference only**, 2026-10-08. This document and its paired stdlib tests do **not** verify production behavior or authorize any target interaction.

## Scope

A finding/evidence record may become unavailable because of retention expiry, consent withdrawal, or an authorized deletion request. Its removal must not silently appear as a never-existing artifact or create a new evidence reference under a different tenant. The storage owner should determine how to retain a minimally identifying, privacy-preserving audit tombstone consistent with retention and deletion obligations.

## Required transition invariants

1. Bind the transition to the **same tenant and exact evidence identifier**, not a name/substring/normalized alias.
2. Keep the previously attested evidence digest as a historical *commitment* where lawful; the tombstone must **never** contain deleted raw evidence.
3. Accept a transition only from an exact `active` predecessor, with nonnegative integer sequence and canonical lowercase 64-character SHA-256 hex commitment. Do not treat this syntactic validation as cryptographic authenticity.
4. Include a bounded, nonempty deletion reason without control characters, CR/LF, DEL or Unicode line separators, and an explicit monotonic sequence; reject boolean, string or skipped sequence values.
5. Bind the new receipt to the exact predecessor receipt seal, rejecting stale predecessors and rewritten hashes.
6. A tombstoned entry is terminal: no resurrection or second deletion under the same identity. New evidence requires a new ID and normal admission/authorization.
7. Searches, exports, twin materialization, remediation context and retests must **fail closed** when the referenced record is tombstoned; never substitute another tenant's or another version's evidence.
8. Treat erasure requests, encryption key destruction and retention of digest/metadata as separate policy decisions. Do **not** retain a digest when it may violate applicable erasure rules.
9. Authenticate issuer identity and authorize the delete actor in production. The reference test deliberately does **not** model trusted issuers or storage transactions.

## Acceptance and integration handoff

`tests/test_evidence_tombstone_integrity_reference.py` contains an offline in-memory model: one eligible deletion and denial cases for tenant/evidence swap, digest rewrite, missing or oversized reason, predecessor mismatch, nonmonotonic sequence, post-tombstone modification, non-deletion transition, invalid predecessor lifecycle/sequence/digest, reason control-character injection, Unicode plain-text control, dataclass subclass spoofing and input mutation.

Production owners should add transactional database tests covering concurrent delete/read, replays and crash recovery; link delete receipts to an issuer-signed audit chain; ensure read/export paths filter tombstones; and run hosted plus permanent-VPS exact-head validations before claiming release readiness.

**Boundary:** no production files edited, no network access, no scans, no target discovery, no change to approval/scope/capability gates. This branch is intentionally separate from currently active evidence hash, attachment-name and export-gate branches.
