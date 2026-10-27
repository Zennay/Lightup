# W33 — Opt-in canonical Unicode evidence write admission (source-owner reference)

**Incubate / M3/M7 PLAN/LAB — DRAFT/HOLD/NO MERGE/NO DEPLOY.** Stacked on independent [W32 expected-RED draft #1212](https://github.com/Zennay/Lightup/pull/1212) fixed head \`23b2885f00a686e61b4c54ea666cee3f3ce36dc1\` (itself an add-only child of #857). Original #857/#828 \`domain.py\` writer/read owner and main are not edited.

## Material implementation

New opt-in \`checked_written_evidence_references_w33\` and \`record_finding_checked_unicode_optin_w33\` inspect a canonical exact tuple before calling existing \`DomainStore.record_finding\`. The helper:

- Preserves intentionally empty manual evidence and authentic original ordered string values, without Unicode rewrites or trimming.
- Restricts exact built-in tuple and member types, max 128 references, at most 4096 UTF-8 bytes each and 262144 UTF-8 bytes of **current DomainStore default JSON serialization** (which may expand non-ASCII into escapes).
- Refuses invisible format/control/bidi and surrogate code points, non-ASCII separators, unanchored Unicode combining/variation marks (including marks after punctuation), explicit U+034F combining grapheme joiner, leading/trailing whitespace and NFKC-equivalent duplicate identities. Preserves normal accented text, emoji with attached variation selectors, ordinary literals and stable reference ordering.
- Fails entirely before calling the existing persistence method. The existing store's operator and engagement checks are delegated, *not replaced or bypassed*. No authorization or provenance decision is created.
- Refuses a polymorphic \`DomainStore\` object at this optional boundary. That policy is provisional pending original source owner compatibility review.

Twelve synthetic \`unittest\` methods exercise **genuine disposable-SQLite writes** and readback, invalid input refusal before writer invocation, exact stored data retention, JSON representation inflation, duplicate compatibility IDs, Unicode positive fixtures and unchanged operator role enforcement, exact positive 4096-byte reference and 262144-byte serialized JSON budgets, and one-byte-over-budget pre-writer refusal. The predecessor W32 tests remain **six intentional expected failures against the original default writer**. A green branch is not evidence that the default writer is fixed.

Run on exact head:

\`\`\`sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_write_unicode_guard_optin_w33.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
\`\`\`

## Review requirements

The NFKC-equivalence policy, default JSON size ceilings and printable-character criteria are provisional. They are *not* evidence authenticity, semantic provenance, tenant/session verification, remediation success or independent retest. The original #857 source owner must decide whether and how to integrate with #828 tenant read lineage, #856/#886 historical decoding, #1207 reference identity, and all writer/reader consumers without incompatible historical data. Privacy/security review, current-main composition, permanent exact-head registered self-hosted VPS CI and explicit release approval remain mandatory. No live clients/targets, grants, scans, credentials, fixes or deployments.
