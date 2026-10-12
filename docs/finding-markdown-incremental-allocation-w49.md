# W49 — independent incremental Markdown allocation characterization

Parent: W48 independent [draft #1224](https://github.com/Zennay/Lightup/pull/1224) **immutable** exact head `fa8cf934276bba8f1cf9484a06a3aa37aa31e7ae`; tracks [issue #1221](https://github.com/Zennay/Lightup/issues/1221). This is add-only tests and documentation, not a modification of the W48 owner branch or the default/opt-in renderer.

## Scope and procedure

```bash
PYTHONPATH=src python -m unittest -v tests.test_finding_markdown_allocation_growth_w49
```

- Measure separately a valid escaped Markdown report with **8 unique references** versus **40 unique references**; each reference contains 12 KiB of raw HTML-entity/Markdown-escape-heavy data. Both stay under source 1 MiB and escaped-output 2 MiB caps. Check growth in returned artifact size while requiring **Python-tracked incremental peak allocation** below 32 MiB for each and **peak difference** under a conservative lab-only 24 MiB budget. Record data privacy/immutability.
- Prove a 1,000,000-codepoint source field triggers the exact `ValueError` integrity refusal **before any category/normalization Unicode walk on that field**, and before escaping. Measure incremental peak under the same provisional budget; ensure input unchanged and no partial output.
- The tests use `gc.collect()` and `tracemalloc` after all input strings are preallocated. Allocation peak excludes the caller's source objects, C/native allocator, RSS/fragmentation and downstream Markdown→HTML conversion, and cannot substantiate hard memory/time limits. The threshold is **only a regression tripwire**, not an enforceable runtime cap.

## Independent release evidence

- Python 3.11 and 3.14 exact-head hosted offline unit + real producer integration: **not accepted until completed success**.
- Registered permanent vps-bb300bba self-hosted LightUp CI exact-head: **not accepted until completed success**.
- Installed downstream HTML/math/linkification/XSS and privacy/redaction, actual tenant auth, latest-main compatibility, original source owners #894/#100/#732 and human signoff: **not established** by synthetic Python checks.

**LightUp remains Incubate, M3/M7 PLAN/LAB ONLY. DRAFT/HOLD/NO MERGE/NO DEPLOY.** No real client data, scans, external targets, credentials, grants, executed fixes or retests.
