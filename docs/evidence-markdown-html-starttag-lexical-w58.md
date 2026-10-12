# W58 — exact raw start-tag lexical gate in optional downstream HTML reviewer

**Posture:** LightUp Incubate M3/M7, PLAN/LAB ONLY — **DRAFT / HOLD / NO MERGE / NO DEPLOY**. W58 is an *uninstalled laboratory reviewer only*. It is not an HTML5 tokenizer, Markdown renderer, real-browser/XSS assessment, deployed mitigation, tenant privacy guarantee or customer retest.

## Immutable lineage / collision boundary

- Parent: W57 [DRAFT #1234](https://github.com/Zennay/Lightup/pull/1234) immutable authored HEAD `b48a84e777928f7e2d396a6c3584f757ea24a57d`.
- W58 own branch `test/evidence-w58-html-starttag-lexical-20261012`, changing only the existing **test-only** `tests/markdown_html_downstream_contract_w51.py`, six new synthetic tests and this new runbook.
- Do not modify original source owners #894/#100/#732, default runtime renderer/reporting/CLI/web/auth, `main`, sibling worker branches, live clients or external targets.

## Independently reproduced discrepancy

Standard-library `html.parser.HTMLParser` can normalize malformed raw opening tokens `<p/ >`, `<p / >`, `<br / >` and `<hr / >` to allowlisted start tags **without attributes**. Earlier W55 bounded raw tokens and W57 checked raw closing tags but did not verify exact raw start-tag lexemes, so some of these fragments met the synthetic contract despite malformed source bytes.

W58 adds a linear allowlist check *after* W55's 4 MiB UTF-8 ceiling and raw token completion, *before* HTMLParser: a literal raw opening token must be exactly an allowlisted case-insensitive tag name (`<p>`, `<H2>`, etc.), or one of the two standard self-closing syntaxes for void tags (`<br/>`, `<hr/>`, `<br />`, `<hr />`). This is deliberately narrower than HTML5. Whitespace-only `<p >` is refused as ambiguous; intentional escape sequences `&lt;p/ &gt;` remain literal visible text. Original `ValueError("invalid downstream finding html integrity")` and pure-input contract remain intact. No file output or mutable report state.

## Offline reproducibility

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_markdown_html_downstream_contract_w51 \
  tests.test_markdown_html_entity_canary_w53 \
  tests.test_markdown_html_unicode_canary_w54 \
  tests.test_markdown_html_truncated_markup_w55 \
  tests.test_markdown_html_adapter_exception_boundary_w56 \
  tests.test_markdown_html_endtag_suffix_w57 \
  tests.test_markdown_html_starttag_lexical_w58
```

Six W58 synthetic tests cover malformed slash/space normalization for non-void/void tags, ambiguous whitespace-only openings, poisoned adapter, balanced ASCII case + international text positives, and escaped literal text plus inherited text-only adapter. These are **acceptance tests only**, not evidence of installed engine/browser behavior.

## Independent release hold

Record exact-final-head GitHub-hosted offline Python 3.11/3.14 **unit plus real-producer integration** raw logs, *separately* exact-final-head permanently registered VPS CI, original source owner and independent security/privacy/tenant authorization review, real pinned Markdown→HTML/parser/extensions config, DOM/browser/CSP, current-main safe composition and explicit release authorization. Queued VPS CI is not acceptance; hosted green does not authorize merging/deployment. No real assets, client data, scans, grants, executed remediation or verified retest.
