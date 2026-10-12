# W48 independent Markdown allocation and atomic-refusal acceptance (#1221)

**Status:** synthetic, offline, add-only tests on immutable W46 `c5b19458e2417d8bccac802ce4809c3332c579e0`. This is an independent sibling of draft #1222, not a patch to #1222 or any production source. LightUp remains **Incubate / M3-M7 PLAN/LAB ONLY / DRAFT-HOLD-NO MERGE-NO DEPLOY**.

## Reproduce

```bash
PYTHONPATH=src python -m unittest -v tests.test_finding_markdown_allocation_boundaries_w48
```

Eight isolated standard-library `unittest` methods cover:

1. Forty **distinct** near-limit HTML-entity/Markdown-escape-heavy evidence references, including exact escaped-token counts and no private metadata emitted.
2. Duplicate exact evidence references rejected before calling the escape function; note sibling #1222's original success fixture used identical references and therefore conflicts with the W43 duplicate admission gate.
3. 16,384-byte UTF-8 field accepted and 16,385+ byte fields deterministically rejected; ASCII and multibyte controls.
4. One-million-character field denied without invoking escape.
5. 65 distinct near-limit evidence references crossing the accumulated **1,048,576-byte** input ceiling, rejected before any escaping.
6. A rejected final row, after a large valid prior row, preventing any prior-row rendering.
7. Source-under-1-MiB but escaped-output-over-**2,097,152 bytes**, refused without returning partial report.
8. Empty report and ordinary accent/emoji variants, deterministic output, metadata redaction and caller-input purity.

The refusal helper checks the **exact** `ValueError` type and message, caller-owned evidence/metadata/fields unchanged, and a conservative **32 MiB Python-tracked peak** `tracemalloc` allocation tripwire on rejection paths. The positive acceptance tests also measure the Python-tracked peak. Each measurement starts after inputs have already been allocated and after `gc.collect()`; this is **incremental interpreter-tracked allocation only**, not total process RSS, maximum source-object memory, allocator fragmentation, peak native library use, adversarial CPU-time proof, or a deployable memory SLA. The threshold is a diagnostic regression budget, not a formal bound.

## Evidence matrix and release gates

| Evidence | State |
| --- | --- |
| Test source checked in to independent W48 branch | Required; reference exact git HEAD |
| Hosted offline Python 3.11 test + integration results | Pending exact-head run |
| Hosted offline Python 3.14 test + integration results | Pending exact-head run |
| Registered permanent `vps-bb300bba` self-hosted LightUp CI | Pending **completed exact-head success**, queued is not success |
| Installed downstream Markdown-to-HTML/math/linkification/XSS and privacy/redaction review | **Not proven** by these unit tests |
| Tenant access, auth/session boundaries and source-owner review (#894/#100/#732) | **Not proven** |
| Safe current-main composition, historic compatibility, explicit human approval | **Not complete** |

**No actual external asset/target interaction, client data, customer scanner, active remediation, credential use, retest, merge, deployment or authorization grant.** These tests do not change `models.py`, `reporting.py`, DomainStore, default Markdown rendering, CLI, installed web, auth, or main.
