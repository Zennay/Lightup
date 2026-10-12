# W60 — opt-in synthetic HTML depth preflight (#1221)

Parent: W59 draft PR #1237, immutable head `a2f0c7d0e5bb4497dff0787a43b34f8362899876`. This child is **add-only** and modifies neither W51/W59 nor the installed/default Markdown renderer, HTML engine, web routes, tenant checks, scope authorization or main.

## Contract

`tests/markdown_html_depth_guard_w60.py` rejects more than 64 simultaneously open non-void HTML elements, malformed nesting, invalid input type, invalid UTF-8 and fragments exceeding 4 MiB UTF-8 **before** calling the existing W51 conservative synthetic HTML reviewer. `br` and `hr` do not count toward nesting. W51 remains responsible for allowlisted tags, attributes, raw lexical integrity, synthetic privacy canaries and required visible evidence markers. No fragment is returned on failure.

`PYTHONPATH=src python -m unittest -v tests.test_markdown_html_depth_guard_w60`

This is a lab-only guard and a conservative policy choice, **not** proof of real Markdown-to-HTML conversion, browser DOM behavior, sanitizer effectiveness, memory/RSS upper bounds, privacy/redaction for actual client data, tenant authorization or a verified remediation. Tests use invented strings only; no network/target interaction.

## Release gates

Confirm exact-head hosted Python 3.11/3.14 tests and producer integration, exact-head registered permanent VPS CI, independent security/privacy review, actual pinned renderer/browser/CSP tests, original source-owner review, latest-main compatibility and explicit release approval. M3/M7 PLAN/LAB — **DRAFT/HOLD/NO MERGE/NO DEPLOY**.
