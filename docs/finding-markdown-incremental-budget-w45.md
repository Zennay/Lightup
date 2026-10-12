# W45 — incremental rendered-budget enforcement for optional Markdown evidence

**M3/M7 PLAN/LAB ONLY. DRAFT/HOLD / NO MERGE / NO DEPLOY.** Narrow child of [W44 draft #1217](https://github.com/Zennay/Lightup/pull/1217), immutable parent `d8f63a2760279e92542ccbd14bf6455c65e92e2d`. Only the existing **uninstalled** W31 escaped-Markdown helper changes; one new synthetic test module. Existing `models.py`, `reporting.py`, `domain.py`, web/CLI, deployment, auth, main and other worker-owned files remain unchanged.

## Concrete gap and fix

W44 checked the 2,097,152-byte UTF-8 limit *after* fully escaping and accumulating every report line in memory. This rejects oversized returned artifacts but allows temporary accumulation of much larger escaped line arrays. W45 replaces the post-construction pass with `append_line()`: after fully validating **all** findings and evidence, each escaped line is UTF-8-byte-counted, including the joining newline, and refused **before** it is appended if it would exceed the cap. Further findings/evidence lines are not escaped on failure. Retains the exact valid output, report order, literal escaping, Unicode admission, 128/128 cardinalities, unique per-report finding identity and within-finding evidence identity, and empty fallback. No partial string is returned; caller-owned data is not changed.

This constrains *retained report lines* to the configured output budget. It is **not** a full memory/CPU bound: snapshots are constructed first (1 MiB raw budget), a single escaped line is constructed before checking, and Python object overhead/temporary allocations remain; no real Markdown renderer has been security-reviewed. The 2 MiB ceiling is provisional.

## Deterministic synthetic acceptance

`tests/test_finding_markdown_incremental_budget_w45.py` tests:
- Exact UTF-8 ceiling preserves byte-identical international text and HTML entity escaping.
- One byte under the required ceiling refuses the entire result without caller mutation.
- Exhausted budget stops escaping before later findings.
- Malformed late evidence is rejected during the whole-batch admission phase, before any rendering.
- Heavy quote-to-HTML-entity expansion is refused without escaping all later evidence.
- Empty report fallback is unchanged.

Run focused and full tests on the **exact branch SHA**:
```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_incremental_budget_w45.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

Release still requires original [issue #894](https://github.com/Zennay/Lightup/issues/894), source owners #100 (`models.py`) and #732 (`reporting.py`), historical compatibility, actual downstream Markdown security/privacy/HTML tests, independently registered **permanent** VPS self-hosted exact-head CI, latest-main composition and explicit authorization. Hosted diagnostic CI alone does not approve merging or deployment. No targets, clients, scans, evidence claims, actual remediation or verified retests occurred.
