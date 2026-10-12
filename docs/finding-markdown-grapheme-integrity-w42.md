# W42 — opt-in Markdown grapheme integrity hardening

**M3/M7 PLAN/LAB only — DRAFT / HOLD / NO MERGE / NO DEPLOY.** This is a narrow stacked correction to W31 [Draft PR #1211](https://github.com/Zennay/Lightup/pull/1211), immutable parent `f1752c849ee40b81bb8a5bc8df582b81ccf5601b`. Source ownership is confined to W31's own previously added optional `src/lightup/finding_markdown_escaped_optin_w31.py`. The default `models.py`, `reporting.py`, authorization, persistence, web/CLI and `main` are unchanged.

## Reproduced gap

W31's displayed-text admission used `has_base=True` after **any** Unicode character other than marks/spacing. This allowed a combining mark or variation selector after *punctuation* to be considered anchored (for instance `"ref:\u0301"` or `"ref_\ufe0f"`), and did not specifically reject U+034F COMBINING GRAPHEME JOINER after a letter. Such text can confuse human reading and reported reference identity. This is a presentation-integrity ambiguity, **not** a demonstrated cross-tenant exploit, a proof of XSS or an actual client incident.

## Material correction

- Reject literal U+034F before considering mark anchoring, including when a preceding base letter exists.
- Allow a combining/variation mark only when the nearest most recent non-mark, non-whitespace character is category **L/N/S** (letter, number, or symbol). Unicode punctuation **P** is not a valid base and resets anchoring.
- Preserve normal accents after letter/number, emoji variation selectors after symbols, original UTF-8 text, existing Markdown+HTML escaping, size limits, metadata omission and atomic all-row preflight.
- No raw evidence is normalized, trimmed, written to durable storage, or released on invalid input.
- The strict category policy is provisional pending locale, renderer, UX and source-owner review.

## Acceptance

`tests/test_finding_markdown_grapheme_integrity_w42.py` adds **8 synthetic in-memory unittest methods**: punctuation anchor permutations, U+034F variants, valid accents/emoji, all displayed fields including evidence, late-row atomic denial, unchanged source and established markup escaping behavior.

Run on the **exact PR head**:
```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_grapheme_integrity_w42.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

Do not reuse green hosted checks from the immutable W31 parent. Exact-head hosted diagnostic and registered permanent self-hosted VPS CI, original issue [#894](https://github.com/Zennay/Lightup/issues/894), `models.py` owner #100 and `reporting.py` owner #732, downstream Markdown renderer security/privacy tests and final main integration are independent release requirements. This does **not** activate any target assessment or prove verified remediation/retest.