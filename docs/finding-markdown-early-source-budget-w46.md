# W46 — early UTF-8 input-budget refusal in optional Finding Markdown

**DRAFT/HOLD — Incubate M3/M7 PLAN/LAB only.** Narrow child of W45 [draft #1218](https://github.com/Zennay/Lightup/pull/1218) at immutable parent `ddc50d92412419116db99e31d43a2e09e0266e04`. Only the previously introduced *uninstalled* escaped-Markdown reference renderer is edited. No `models.py`, `reporting.py`, DomainStore, authentication, deployment, standard web/CLI or main edits.

## Gap, correction and limits

Previously `_checked_literal` called `strip()` and UTF-8 `encode()` on an arbitrarily long exact built-in string before checking its 16,384-byte per-field limit. Even when rejected, a 1,000,000-character source causes scanning and an unnecessarily large temporary encoded allocation. The 1,048,576-byte cumulative input limit was also checked *after* visiting all evidence references in a finding.

The optional reference now applies a mathematically safe **codepoint-count lower bound**: UTF-8 encodes any valid code point into **at least one byte**, so `len(value) > 16384` cannot possibly fit in 16,384 UTF-8 bytes and can be rejected *before* stripping, encoding or Unicode walking. It **still checks the true encoded UTF-8 byte count** for non-ASCII inputs and rejects surrogates, malformed identity/type, Unicode controls or invalid grapheme anchors as before. It also checks the cumulative UTF-8 source budget **after each field and evidence reference** and refuses as soon as admitting another would exceed 1 MiB. No accepted scalar semantics, default output, report order or in-place mutation should change.

### Seven deterministic offline regression methods

`tests/test_finding_markdown_early_source_budget_w46.py` checks: huge million-character field is denied without any Unicode scan/escaping; exact character and multibyte UTF-8 boundaries; noncanonical/blank/surrogate input refusal; exact cumulative byte boundary and one-byte-over denial; short-circuit before validating all later evidence; atomic late invalid input; unchanged Unicode/order and empty report fallback.

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_early_source_budget_w46.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

### Unchanged gates

This improves *rejection work* only. It does not ensure constant-memory allocation (the source object is already held by the caller, and Python snapshots, escaped lines and object overhead still exist), is **not** a new sanitizer, does not redact secrets or verify provenance, and does not make authorization, tenant isolation, HTML rendering or verified retest claims. Reference field/batch sizes are provisional. Requires [issue #894](https://github.com/Zennay/Lightup/issues/894), original owner PRs #100 / #732, independent actual Markdown/privacy/security review, historic compatibility, exact-head self-hosted permanent VPS CI, latest-main integration and explicit release approval. No clients, targets, scope grants, real scans, executed remediation, verified retests, merge or deployment.
