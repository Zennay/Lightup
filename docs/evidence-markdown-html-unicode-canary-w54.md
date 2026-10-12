# W54 — Unicode-obscured synthetic private HTML canary (issue #1221)

**Scope:** isolated opt-in reviewer contract, stacked on immutable W53 DRAFT #1230 at `f9048b01c372969dbbb1b2ca3e27ba85cc399256`. Incubate M3/M7 **PLAN/LAB ONLY**. **DRAFT / HOLD / NO MERGE / NO DEPLOY**.

## Finding and narrow fix

W53's bounded (eight-pass) HTML entity decoding refuses direct/multiply-encoded private metadata, but a synthetic marker with U+200B ZERO WIDTH SPACE, U+200D JOINER, U+2060 WORD JOINER, U+FE0F variation selector, bidi formatting, or NFKC-compatibility character inserted within it no longer contains the exact ASCII sentinel. The W53 helper could accept a conservative HTML fragment that visually or canonically obscures its *laboratory* private marker. This is a diagnostic false negative, **not** evidence of an installed security defect, exploit or customer incident.

W54 makes a narrow change **only in the uninstalled optional W51 HTML test helper**:

- Check the synthetic marker in original text and a *refusal-only* NFKC representation with selected zero-width/format/variation codepoints removed.
- Apply the check at each bounded HTML unescape step, both to source HTML and HTMLParser-visible concatenated text, preserving the strict 4 MiB input ceiling.
- Keep source fragment, original Finding, metadata, and emitted HTML untouched; no normalization or deletion is persisted or returned.
- Refuse on the established exact `ValueError("invalid downstream finding html integrity")`; preserve ordinary international text, emoji ZWJ sequences, variation selectors, and safe escaped markup **unless they obscure the synthetic marker**.

Seven new synthetic test methods cover raw invisibles, singly/doubly entity-encoded controls, NFKC compatibility confusables, concatenated allowed-tag splits, a poisoned adapter, positive Unicode/emoji controls and existing safe text-only adapter. Fixtures never include real data.

## Validation

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_markdown_html_downstream_contract_w51 \
  tests.test_markdown_html_entity_canary_w53 \
  tests.test_markdown_html_unicode_canary_w54
```

Record actual **exact final HEAD** once the branch is stable. GitHub-hosted Python 3.11 and 3.14 offline unit/integration jobs and registered **permanent** VPS `[self-hosted,zcloud,vps]` jobs must be distinguished. A queued VPS run is not a pass; neither hosted tests nor marker-matching prove memory bounds, actual Markdown→HTML engine behavior, DOM/browser/XSS, CSP, tenant permission or real secret redaction.

## Release controls

- Do not edit original #894/#100/#732 Finding/report owner files, default models/report/web/auth/CLI, another worker branch, or main.
- Pin and independently validate the *actual* downstream Markdown engine, version, parser flags, extensions and browser policy before considering integration.
- Independent source-owner, security/privacy and tenant-auth reviews, latest-main compatibility, exact-head permanent VPS CI and explicit owner authorization are mandatory.
- No real client/target interactions, scans, grants, retests, live changes or production deployment. **DRAFT/HOLD/NO MERGE/NO DEPLOY**.
