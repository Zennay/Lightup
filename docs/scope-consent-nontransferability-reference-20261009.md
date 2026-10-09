# Scope consent must not transfer across ownership boundaries

Status: **offline reference / DRAFT / HOLD**. This contract does not issue grants, approve scans or activate targets.

An approval for tenant A, engagement A, owner A, asset A and capability A must never become valid for tenant B, a successor engagement, changed owner, reassigned asset, or another capability merely because another identifier remains the same. A new explicit source-owner-confirmed approval is required after ownership transfer. A revision change or revocation independently denies admission.

## Reference acceptance scenarios

The companion test uses an in-memory frozen tuple-shaped consent model and checks:
- exact positive fixture (reference predicate only);
- tenant, engagement and owner crossover denial;
- asset and capability substitution denial;
- stale revision and revoked consent denial;
- owner-transfer round trip cannot resurrect an earlier approval: fresh authorization revision is required;
- matching revision cannot override an independently revoked authorization;
- revision identifiers must be positive exact integers, never zero, negative or bool;
- identity bindings containing ASCII control characters or DEL must fail closed on either side, including when both sides carry the same malformed identifier. The regression fixtures generate actual U+0000, TAB, LF, CR and DEL codepoints with `chr`, never string-escape lookalikes;
- strict booleans, integer revision and exact built-in string identity types;
- empty identity and malformed revocation denial;
- false-y nonboolean revocation status, denied approvals and forged stored owner identity;
- case changes, trailing spaces and Unicode lookalikes cannot silently transfer authority;
- hostile consent objects and subclasses cannot trigger user-defined attribute access before admission; foreign request objects cannot invoke coercion or equality.

Run offline: `python -m unittest discover -s tests -p 'test_scope_consent_nontransferability_reference_20261009.py' -v`.

The reference now additionally mutates every stored identity field independently, and independently mutates every requested field. These tests detect partial-key comparisons that accidentally ignore tenant, engagement or capability.

## Production integration obligations (not implemented here)

The trusted source owner must bind approvals to verified tenant, engagement, owning principal, canonical asset, capability, approval revision and revocation generation. Independently revalidate atomically immediately before any target I/O and prohibit inferred transfer on sale, tenant move, reassignment, ownership change or reused asset identifiers. Explicit user authorization and review remain required. Integration must prove **zero executor/evidence handler calls** on denial and cover race conditions on revocation or ownership transfer. No target-facing tests are enabled by this PR.

Do not merge, deploy or activate based on this reference. Require exact-head hosted and canonical permanent VPS CI plus source-owner review of #107/#1128 and revocation #100.

Additional offline hardening: identity comparison rejects U+200B zero-width space, U+202E right-to-left override and lone UTF-16 surrogate codepoints to prevent hidden/surrogate identifiers from silently inheriting consent. This is not a full Unicode normalization policy or executable authorization.

The offline identity fixture now rejects all Unicode `Cc`, `Cf` and `Cs` categories, including bidi isolation, joiners and word joiners, across each consent binding. This is only a conservative reference boundary: trusted issuer validation and production owner review remain separate requirements.

Stored consent identifiers receive the same Unicode format-control checks as request identifiers, including when both strings are identically contaminated; an exact textual match does not make malformed identities authoritative.

Positive/negative Unicode controls: ordinary letters and combining marks are accepted only when the persisted owner ID exactly matches the request. Canonically equivalent composed/decomposed strings do not implicitly confer authority; the trusted issuer must define canonical identity rules independently.

Further offline edge controls exercise both ends of the Unicode surrogate range and verify that combining-mark suffixes on tenant, engagement, asset or capability IDs cannot silently inherit exact-match consent.

Revision-binding checks also vary stored and requested revisions independently. Approval status must be an exact builtin boolean; numeric, string, missing, and container-shaped impostors fail closed even if they look truthy or falsey.

Unicode line and paragraph separators (Zl/Zp: U+2028/U+2029) are rejected in consent identifiers to prevent audit or serialization boundary confusion. Fixtures use actual characters from chr(), not literal backslash sequences.

Stored-record Unicode Zl/Zp separator contamination is denied even if a submitted request exactly repeats the same contaminated identifier; exact equality alone never validates malformed identity metadata.
