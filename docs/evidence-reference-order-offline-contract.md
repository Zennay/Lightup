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

Twenty-five stdlib-only offline reference tests. Additional vectors cover the 64-member limit (accepted) and 65-member denial, tuple/list parity, case-sensitive identity, composed versus decomposed Unicode, exact whitespace, JSON delimiter ambiguity, tenant/finding boundary separation, membership extension, and escaped versus literal control sequences, accepted exact-length identity boundaries, independently rejected finding identifiers, quoted identifier distinction, and deterministic repeated replay. No source changes, network access, real target assessment, CI-green claim, production enforcement, or authorization expansion. Production source owners must establish collection semantics, evidence provenance and retest synchronization before integration. Require exact-head hosted and permanent VPS validation before promoting the draft.

## Domain separation and compatibility

The offline digest now includes the explicit schema marker `lightup.evidence-set.v1` inside canonical JSON before SHA-256 hashing. This makes a v1 evidence-set receipt distinguishable from unversioned payloads or future unrelated receipt formats. Versioning here is only a proposed offline contract: do not silently reinterpret previously issued digests. A production migration would require explicit version dispatch, backward-compatible verification policy, and issuance provenance under the production owner's review. The tests assert the exact canonical encoding and that the legacy unversioned digest differs.
