# W53 — nested HTML entity privacy-canary admission (issue #1221)

**Status:** opt-in synthetic evidence-only. Incubate, M3/M7 PLAN/LAB. **DRAFT / HOLD / NO MERGE / NO DEPLOY.** Parent W51 draft PR #1228 exact immutable commit `e04e07a4512144d4285c1e2bf4189f593d44468e`. This W53 child updates only W51's uninstalled test-facing acceptance helper, creates a new test module and this note. Original renderer/model/reporting source owners (#894/#100/#732), default app, CLI, tenant APIs, main, targets and other workers are untouched.

## Concrete gap and narrow mitigation

The original W51 canary check decoded HTML character references only once on the raw fragment and once on concatenated HTML-parser-visible text. An offline fragment with `&amp;amp;#83;YNTHETIC-W51-METADATA-PRIVATE` could pass those checks, even though additional review/decoding reveals the intentionally private marker. This weakens the **synthetic evidence/privacy diagnostic**; it does **not** establish a real application data leak or browser XSS.

The W53 optional helper now inspects both original fragment and concatenated visible text with bounded repeated `html.unescape`. It refuses any observed diagnostic private marker and refuses strings still changing after eight passes. This is conservative, including deeply nested but benign entities. No normalized content is returned or persisted. The pre-existing max 4 MiB HTML byte check, parser allowlist, zero-attribute rule, required section markers, and immutable source Finding check still apply.

## Test acceptance

```bash
PYTHONPATH=src python -m unittest -v tests.test_markdown_html_downstream_contract_w51 tests.test_markdown_html_entity_canary_w53
```

New isolated W53 tests cover raw, decimal/hex, single-/double-/triple-/fourfold entity-encoded private metadata, tags splitting the synthetic canary, undecidable nesting depth, benign encoded Unicode/markup and original safe-text adapter control. Inputs contain only invented local data. Existing W51 tests must remain green. No installed downstream renderer is selected or exercised.

## Independent release gates (all unresolved until proven separately)

- Record **exact branch SHA** and separately inspect unit and real-producer integration log conclusions for Python 3.11 and 3.14. Hosted green is diagnostic only.
- Permanent registered self-hosted VPS workflow `[self-hosted,zcloud,vps]` **on exact SHA** must finish successfully; queued status is not acceptance.
- Select an actual pinned/configured Markdown-to-HTML renderer and independently test DOM/browser, CSP, entity handling, math, hyperlinking, privacy, tenant access, memory and latest-main composition.
- Original source owners, independent security/privacy reviewer and explicit release approval remain mandatory. This module does not become a default renderer or authorize any production operation.

No real customer evidence, scanning, assets, grants, executed remediation or verified retest. The test-only private canary is **not** a comprehensive secret detector.
