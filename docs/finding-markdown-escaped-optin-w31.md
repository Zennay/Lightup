# W31 — Alternative opt-in escaped Finding Markdown (#894 / #732)

**M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.** Independent alternate proposal stacked above immutable W28 [draft #1206](https://github.com/Zennay/Lightup/pull/1206) head \`d746c8d2ed2cbc20319d26bda55a90dc8248801e\`. No default source, web/CLI, \`models.py\`, \`reporting.py\`, DomainStore or main edit.

## Why a second implementation

W28 rejects malformed legacy evidence but allows Markdown and HTML control syntax through the original \`render_markdown\`. W29 [draft #1208](https://github.com/Zennay/Lightup/pull/1208) refuses even harmless Markdown punctuation and URLs. This **separate, opt-in** renderer instead escapes literal user text after validating a conservative single-line Unicode/UTF-8 input contract. A source owner can compare behavior and choose a reviewed production-compatible approach. This is not installed.

## Concrete semantics

- All findings and evidence strings must be exact canonical types with known enums. Every finding is fully checked before *any* Markdown is constructed; corrupt late rows abort the entire artifact.
- UTF-8 caps: **16,384 bytes per displayed field**, **1,048,576 bytes across displayed input**, at most 128 findings and 128 evidence references each. These are provisional limits requiring compatibility approval.
- Reject control/bidi/invisible format, separator newline, unanchored combining marks, surrogate codepoints and NFKC-compatibility forms that can become markup punctuation downstream; ordinary international letters, URLs, underscores and quotation marks remain admitted.
- Escape Markdown punctuation with backslashes and raw HTML-special text with HTML entities. Encode in this order so entity syntax is not corrupted. Use inline escaped fields rather than placing attacker-supplied text inside backtick code spans, where Markdown backslash escapes are ineffective.
- Snapshot only the displayed fields and evidence into independent tuples; omit arbitrary metadata, never mutate caller findings, never write a file, call a model, interact with a target or authorize a tenant.
- Preserve the existing empty batch and empty evidence fallback presentation. Identity/target formatting intentionally differs from legacy backtick code-span styling and needs owner UX review.

## Acceptance and limitations

The eleven isolated pure in-memory unittest methods in \`tests/test_finding_markdown_escaped_optin_w31.py\` cover canonical Unicode/order, ordinary punctuation/URLs/quotes, literal Markdown, HTML/entity integrity, Unicode/compatibility rejection, late-row atomicity, snapshot isolation, shape/byte budgets, empty-compatibility and a control proving legacy W28 still renders raw Markdown.

\`\`\`sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_escaped_optin_w31.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
\`\`\`

**Never claim universal Markdown or HTML safety without testing the actual downstream renderer(s).** HTML entity handling, renderer-specific autolinks, whitespace and complex Unicode display are renderer-dependent. This helper does not redact secrets, establish evidence provenance, enforce tenant authorization, prove a remediation/retest or guarantee installed ingress safety. Original issue #894, owner #100 (\`models.py\`), #732 (\`reporting.py\`), independent security/privacy review, historical compatibility, actual renderer tests, exact-head permanent self-hosted VPS CI, safe latest-main integration and explicit release approval are all still mandatory. No live target, customer data, grant, scan or deployment.
