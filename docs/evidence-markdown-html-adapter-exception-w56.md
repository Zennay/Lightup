# W56 — fail-closed optional downstream renderer adapter exceptions (#1221)

**Status:** LightUp Incubate M3/M7, **PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY**. This is a synthetic CLI/error-classification test, not an authorization grant, execution sandbox, installed renderer validation, XSS/privacy proof, or browser evaluation.

## Immutable provenance and collision boundaries

- Parent: W55 [DRAFT #1232](https://github.com/Zennay/Lightup/pull/1232) at exact immutable `4bf3575ca745312e3c32298fe7a6d80bfbfbe2ac`.
- New branch `test/evidence-w56-adapter-exception-boundary-20261012`, only a dedicated W56 unittest, an exception-boundary edit to the **uninstalled** `tests/markdown_html_downstream_contract_w51.py` helper and this runbook.
- Leave original #894/#100/#732 owners, real default Markdown/web/CSV/auth/CLI, `main`, other workers, live clients, targets and installed services unchanged.

## Narrow defect and repair

Prior W51 `main(["--renderer", "module:callable"])` caught `ImportError`, `AttributeError`, `ValueError`, `TypeError`, but an explicit renderer raising `RuntimeError`, `OSError`, `TimeoutError` or another `Exception` could propagate an uncaught traceback outside the synthetic acceptance boundary. This is a **lab CLI reliability/error-redaction gap**; no deployed renderer is implied.

W56 classifies exceptions deriving from `Exception` as `REJECTED/INCONCLUSIVE` (exit 1), logging only the exception **type** and never the message/traceback or synthetic private canary. A missing explicit engine remains `INCONCLUSIVE` (exit 2). A passing synthetic escaped-text fixture retains synthetic-only wording; validation errors still deny. Process interrupts inheriting directly from `BaseException` intentionally propagate. Running an arbitrary adapter still executes its code: **no sandbox, timeout enforcement, secret redaction of adapter-owned side effects, or browser security claim**.

## Offline acceptance

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_markdown_html_downstream_contract_w51 \
  tests.test_markdown_html_entity_canary_w53 \
  tests.test_markdown_html_unicode_canary_w54 \
  tests.test_markdown_html_truncated_markup_w55 \
  tests.test_markdown_html_adapter_exception_boundary_w56
```

Six W56 unittest methods exercise five unexpected exception classes, no tracebacks/exception messages, synthetic private-marker non-disclosure, positive deterministic text-only control, bad return denial, missing renderer inconclusive classification, and retained `KeyboardInterrupt` propagation.

For acceptance record **separately**: final exact branch SHA; GitHub-hosted Python 3.11 and 3.14 unit logs **and** real-producer integration logs; registered permanent self-hosted VPS CI exact SHA; source-owner + independent security/privacy/tenant review; actual pinned Markdown renderer/DOM/CSP; safe latest-main compatibility; explicit human release authorization. Passing hosted CI is **not** VPS acceptance. No scans, real findings, remediation execution, retests, client data, or production deployment.
