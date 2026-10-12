# W57 — reject malformed raw HTML end-tag suffixes (#1221)

**Posture:** LightUp Incubate M3/M7 PLAN/LAB ONLY — **DRAFT / HOLD / NO MERGE / NO DEPLOY**. This is a tiny **uninstalled synthetic reviewer** contract change, not a deployed renderer, HTML5 tokenizer, sanitizer, browser/CSP proof, or customer remediation.

## Collision-safe provenance

Parent is immutable W56 [DRAFT #1233](https://github.com/Zennay/Lightup/pull/1233) at exact `52a1743b5a827bf144ca3769bafd795811d8a4b1`. Branch `test/evidence-w57-html-endtag-tail-20261012`. Scope: existing **tests-only** W51 strict reviewer, six new W57 unittests, and this new runbook. No original #894/#100/#732 source-owner files, default reporting, web/auth/CLI, main, other branches or live targets touched.

## Independently characterized parser discrepancy

The Python standard-library `html.parser.HTMLParser` normalizes `<p>W51</p data-x=1>`, `</p unexpected>`, `</p /junk>`, and comparable trailing data into `handle_endtag("p")` callbacks, discarding the suffix. The W55 raw-angle completion pass only checked that each raw token had a terminating `>`, so the earlier conservative lab gate accepted some malformed HTML and lost the exact source-token provenance. This is an **acceptance-contract integrity gap**, not proof of browser interpretation or cross-site scripting.

W57 checks each literal raw closing tag *before* HTMLParser: the bytes between `</` and `>` must be exactly one ASCII-allowlisted tag name (case-insensitive), with no whitespace, attributes or other bytes. Legitimate `</P>`, balanced nested tags, ordinary international text, escaped `&lt;/p attr&gt;` examples and W51's escaped-text adapter continue to pass. The existing 4 MiB UTF-8 source limit and single `ValueError("invalid downstream finding html integrity")` apply; no partial success, mutation or persisted output.

## Offline reproduction

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_markdown_html_downstream_contract_w51 \
  tests.test_markdown_html_entity_canary_w53 \
  tests.test_markdown_html_unicode_canary_w54 \
  tests.test_markdown_html_truncated_markup_w55 \
  tests.test_markdown_html_adapter_exception_boundary_w56 \
  tests.test_markdown_html_endtag_suffix_w57
```

Six W57 regression methods cover multiple parser-swallowed suffixes, attribute/event shapes, a synthetic poisoned renderer, case-insensitive balanced positive fixtures, literal escaped closing-tag text and inherited text-only control.

**Release acceptance remains separate:** independent exact-final-head hosted Python 3.11/3.14 unit and genuine producer integration logs; **registered permanent VPS CI** exact SHA; real pinned Markdown-to-HTML engine/browser DOM/CSP/config; original owners plus independent privacy/security/tenant authorization review; safe latest-main integration and explicit human approval. Hosted success alone is not registered VPS proof. No real client evidence, target scans/interactions, grants, executed remediation, retest or deploy.
