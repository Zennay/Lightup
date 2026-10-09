# Evidence reference ordering: offline reference contract

This reference isolates an evidence/remediation integrity question: a finding's logical evidence membership must be stable when an upstream store returns references in different orders. A canonical digest binds tenant ID, finding ID and exact evidence membership. It rejects duplicates rather than silently hiding upstream duplication, and rejects malformed identities and references. The reference model is in `tests/test_evidence_reference_order_offline.py`.

## Proposed production acceptance

- Treat only explicitly declared *set-like* evidence collections as unordered. Ordered observation timelines must retain sequence and timestamps.
- For set-like collections, sort exact reference bytes for a stable digest; never trim, casefold, Unicode-normalize or resolve aliases without a separately reviewed identity contract.
- Reject duplicate members, malformed types and excessive sizes before producing a receipt.
- Bind tenant and finding identity into any digest; verify source ownership and live evidence existence separately.
- Keep customer payloads out of receipts: digest identifiers, not raw findings or attachments.
- When references are revoked, deleted or superseded, never treat an old digest as current evidence. A receipt is not proof of existence or authorization.

## Limitations and handoff

Thirty stdlib-only offline reference tests. Additional vectors cover the 64-member limit (accepted) and 65-member denial, tuple/list parity, case-sensitive identity, composed versus decomposed Unicode, exact whitespace, JSON delimiter ambiguity, tenant/finding boundary separation, membership extension, and escaped versus literal control sequences, accepted exact-length identity boundaries, independently rejected finding identifiers, quoted identifier distinction, and deterministic repeated replay. No source changes, network access, real target assessment, CI-green claim, production enforcement, or authorization expansion. Production source owners must establish collection semantics, evidence provenance and retest synchronization before integration. Require exact-head hosted and permanent VPS validation before promoting the draft.

## Domain separation and compatibility

The offline digest now includes the explicit schema marker `lightup.evidence-set.v1` inside canonical JSON before SHA-256 hashing. This makes a v1 evidence-set receipt distinguishable from unversioned payloads or future unrelated receipt formats. Versioning here is only a proposed offline contract: do not silently reinterpret previously issued digests. A production migration would require explicit version dispatch, backward-compatible verification policy, and issuance provenance under the production owner's review. The tests assert the exact canonical encoding and that the legacy unversioned digest differs.

## Invalid Unicode boundary

Unpaired UTF-16 surrogate code points are invalid as standalone Unicode scalar values. Python's JSON `ensure_ascii=True` can otherwise escape them and produce a reproducible digest for an identifier that cannot be represented as well-formed UTF-8. The reference now rejects surrogates in tenant, finding and evidence identifiers before canonicalization, while preserving valid supplementary-plane characters. This does not claim production input enforcement; production adapters must independently validate their decoding and identity sources.

## Exhaustive order check and length semantics

The reference checks all 24 permutations of four distinct evidence IDs to prove order independence over that bounded example. Its 128-character limit is based on Python string length (Unicode code points), **not UTF-8 encoded byte length**. Production owners must explicitly approve that distinction or replace it with the intended storage/API byte-limit contract before adopting this reference. These tests remain offline, not evidence of production enforcement or VPS success.
