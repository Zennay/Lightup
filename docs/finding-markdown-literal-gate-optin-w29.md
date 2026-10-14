# W29 — optional literal-line Markdown structural integrity gate

**Status: synthetic M3/M7 PLAN/LAB only; DRAFT/HOLD / NO MERGE / NO DEPLOY.** This is a collision-free conservative follow-up to [W28 draft PR #1206](https://github.com/Zennay/Lightup/pull/1206) for open [#894](https://github.com/Zennay/Lightup/issues/894). W28 checks exact legacy Finding evidence shape and performs all-row snapshots, but deliberately does **not** escape Markdown. The default report renderer accepts arbitrary Markdown control characters in title, target, evidence, ID and remediation.

## Isolated material change

New explicitly invoked `render_literal_checked_findings_markdown` in `src/lightup/finding_markdown_literal_gate_optin_w29.py` checks the entire input batch first and rejects Markdown or HTML syntax and Unicode compatibility/confusable equivalents, invisible format characters, control characters, non-literal multiline data, numeric ordered-list prefixes and noncanonical input types. Checks NFKC for admission but does **not** normalize values; retains literal letters, numbers, spaces and a narrow safe punctuation alphabet. Each row is copied without metadata and each evidence list is detached; only after the entire batch passes does it call W28's opt-in renderer.

The acceptance is intentionally much narrower than ordinary free-text reporting. Examples such as Markdown-formatted remediation, underscores and email punctuation are rejected rather than escaped; legitimate input may be refused. Batch limits 128 findings / 128 evidence entries each, 1024 codepoints per displayed line are **provisional** and need source-owner and UX compatibility approval. There is no report write, no database mutation, no target interaction.

## Synthetic acceptance

`tests/test_finding_markdown_literal_gate_optin_w29.py` includes nine real unittest methods: valid international letters/evidence order, empty compatibility, rejected HTML/Markdown injection examples across all five text-bearing fields, NFKC disguises and Unicode controls, late finding atomic refusal, detached snapshots/no metadata, container and text limits, unchanged previous W28 Markdown gap control, and empty finding compatibility. Run on the exact PR head with:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_literal_gate_optin_w29.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

## What is *not* claimed

This is an opt-in **deny-only display integrity experiment**, not a general-purpose Markdown parser, HTML sanitizer, output encoding specification, personal-data/credential redactor, tenant guard, authoritative evidence attestation, fixed remediation, successful retest or production safety approval. It is NOT wired into the default CLI/WSGI and does not fix `models.Finding.validate()` or `reporting.render_markdown()`. Direct W28 and legacy report callers remain unchanged. There is no installed ingress or proof of race-free concurrent mutation.

PR #100 owns `models.py`, PR #732 owns `reporting.py`; neither file is edited. Owner review must decide between proper Markdown escaping in #732 and strict rejection, integrate only a production-compatible contract, check privacy and historical output compatibility, obtain **exact-head registered self-hosted VPS CI**, safe latest-main composition and explicit release approval. Hosted or isolated tests alone do not satisfy these gates. No real client/target data, active scan, authorization grant, verified remediation or deployment.
