# W55 — fail-closed incomplete HTML tokens in synthetic renderer review (#1221)

**Posture:** LightUp Incubate M3/M7, PLAN/LAB ONLY. **DRAFT / HOLD / NO MERGE / NO DEPLOY.** Stacked child of immutable W54 DRAFT #1231 at `dc2fb829103b04e94c0a31cecb8c6db7ee336e3a`. Changes only W51's **uninstalled reviewer helper**, adds a new synthetic test module and this note. Do not change default application/renderer, real clients, targets, auth, existing owners #894/#100/#732, main or another worker's branch.

## Offline finding

`HTMLParser(convert_charrefs=True).close()` can deliver incomplete raw HTML delimiters such as `<script`, `<!--`, `<p onclick=` as ordinary `handle_data` rather than rejected tags. On a fragment that already has valid `<p>W51</p>`, W51's original allowed-tags/attributes, balance, expected text and privacy checks can therefore all pass, despite dangling unparsed markup. This is a **synthetic acceptance-contract gap**, not a demonstrated browser XSS or installed markdown renderer defect.

## Narrow fix and coverage

Add a linear, bounded raw-angle-token pass *after* the existing strict source-byte limit and *before* HTMLParser. Every literal raw `<` must start an ASCII tag-ish token and have a `>` before the next `<`. Incomplete/doubled or invalid delimiters raise the exact existing `ValueError("invalid downstream finding html integrity")`. It is intentionally conservative and is **not** an HTML5 parser, sanitizer, browser DOM checker or comprehensive XSS proof. Escaped literal `&lt;` / `&gt;`, validated full allowed tags, Unicode, and inherited adapter behavior must remain intact. No data mutation, persistence, install or app routing change.

Six independent synthetic unittest methods cover truncated executable/attribute tails, comments/doctype/PI/dangling angles, nested malformed raw markup, rendered adapter suffix, valid escaped Unicode controls and the inherited safe text-only adapter.

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_markdown_html_downstream_contract_w51 \
  tests.test_markdown_html_entity_canary_w53 \
  tests.test_markdown_html_unicode_canary_w54 \
  tests.test_markdown_html_truncated_markup_w55
```

## Release/validation gate

At exact final SHA require independently reviewed GitHub-hosted offline unit and producer-integrations for Python 3.11 and 3.14 and **separate registered permanent self-hosted VPS CI**; queued status is not proof. Original owner, independent security/privacy/tenant review, real pinned Markdown-to-HTML parser/extensions configuration, DOM/browser/CSP/linkification/math, current-main safe integration and explicit release authorization remain outstanding. No live customer data, targets, scans, grants, executed remediation, retest or deployment. **DRAFT / HOLD / NO MERGE / NO DEPLOY.**
