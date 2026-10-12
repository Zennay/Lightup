# W47 — opt-in Markdown math-dollar literal integrity

**Incubate M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.** Isolated opt-in output-presentation follow-up to [W46 draft #1219](https://github.com/Zennay/Lightup/pull/1219) immutable parent `c5b19458e2417d8bccac802ce4809c3332c579e0`. Only the previously introduced, uninstalled W31 escaping helper is changed; new standalone regression tests and this contract. Default `models.py`, `reporting.py`, DomainStore, installed web/CLI, tenant authorization, current main and other worker-owned paths unchanged.

## Presentation ambiguity

W31 escapes common Markdown punctuation and HTML syntax, but accepted and emitted literal **`$`** without a Markdown backslash. While CommonMark typically treats dollar signs as plain text, some downstream Markdown engines enable math delimiters (`$...$`, `$$...$$`) that can change interpretation of user-supplied finding/remediation/evidence text. W31 also admitted NFKC-compatibility dollar characters such as U+FF04 FULLWIDTH DOLLAR SIGN or U+FE69 SMALL DOLLAR SIGN that normalize to `$` downstream. This is **a conservative renderer-dependent presentation-integrity hardening**, *not* a demonstrated exploit or proof of installed XSS.

## Narrow change

- Add `$` to the existing Markdown literal escape character set; escaped text visibly retains the original source value when processed by appropriate Markdown parsers, without using raw HTML or code spans.
- Add `$` to the forbidden **NFKC-compatibility-to-markup** set. The exact original strings are rejected, **never normalized**; ordinary literal ASCII `$` is accepted and escaped, as are normal currency symbols `€`, `£`, `¥`.
- Retain existing all-finding preflight, Unicode/grapheme controls, per-field and batch UTF-8 budgets, per-line output cap, no metadata retention, no caller mutation and fail-closed no-partial-return semantics.

## Seven synthetic offline unit methods

`tests/test_finding_markdown_math_dollar_literal_w47.py` proves dollar escaping in each displayed field, multiple adjacent math delimiters, two known Unicode compatibility dollar forms, atomic refusal of disguised dollars in any displayed field and late evidence, continued Unicode currency acceptance, and output-cap accounting for added backslashes.

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_math_dollar_literal_w47.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

No general HTML/Markdown engine safety assertion: downstream rendering plugins, linkification and privacy still need independently installed-renderer tests. Original issue [#894](https://github.com/Zennay/Lightup/issues/894) and source owners #100/#732 must evaluate presentation compatibility; real scope authorization, evidence provenance, verified retest, exact registered permanent self-hosted VPS CI, safe latest-main integration and explicit release permission remain unmet. No active targets, client records, scans, scope grants, executed remediation, verified retests or deployment.
