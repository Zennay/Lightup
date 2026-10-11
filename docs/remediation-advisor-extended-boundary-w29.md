# Issue #898 — W29 malformed advisor output / third-finding stop

**Status:** expected-RED tests-only; M3/M7 PLAN/LAB, DRAFT/HOLD, no merge/deploy.

## Immutable source / branch boundary

- Source owner: [draft PR #846](https://github.com/Zennay/Lightup/pull/846), immutable head `26b0ca5e89648c3604ff3b9ca1ba2fab81dd2dd6`.
- Original `src/lightup/ai/pipeline.py` Git blob: `583a365966d6b4d8f2531ecfa715eaf0a231b7fb`.
- W26 existing regression files stay unchanged. W29 adds only `tests/test_remediation_advisor_extended_boundary_w29.py` (blob `a44836eb677bfdf83e134b500b85a80cc24c5b14`).
- No edits to `src/lightup/ai/pipeline.py`, provider/gateway, scope, network, targets, domain, default routes or `main`.

## Reproduced local isolated proof (2026-10-12)

Python 3.13.5, exact original Git blob reconstructed alongside exact gateway code and tests; test module blob verified against GitHub. Run: `PYTHONPATH=src:. python -m unittest tests.test_remediation_advisor_batch_atomicity_w26 tests.test_remediation_advisor_extended_boundary_w29 -v`.

- **Unmodified PR #846 pipeline:** 5 unittest methods; 12 expected subtest failures (blank/whitespace or malformed advisor outputs are forwarded instead of raising).
- **Disposable candidate only:** add a strict `type(advice) is str and advice.strip()` check before `ReviewedFinding` append; 5/5 methods pass. Candidate pipeline Git blob `1e1871d1a1310d4ed19747f1796e21387ef253b1`. This is **not** a remote source commit, full-repository CI or installed-entrypoint proof.
- The W29 cases cover a third finding's blank answer, preserving input and preventing any report call, and invalid provider return types (None, number, bool, list, str subclass) failing before the second finding.
- Local Python compileall passed. No provider network calls or real data.

## Required owner acceptance

The source owner must decide whether strict built-in string validation matches the gateway contract; integrate the minimal guard in the canonical pipeline, run the complete real repository tests and permanent exact-head CI, review composition against current main, and explicitly approve release. Expected RED tests are **not merge-ready**. No client, scan, authorization grant, remediation execution, verified retest or deployment was performed.
