# W50: isolated process RSS characterisation for evidence Markdown (#1221)

**Posture:** LightUp **Incubate / M3–M7 PLAN/LAB ONLY / DRAFT–HOLD / NO MERGE / NO DEPLOY**. Independent add-only child of immutable W48 #1224 at fa8cf934276bba8f1cf9484a06a3aa37aa31e7ae. Does not change canonical models.py, reporting.py, domain/web/auth/CLI, default renderer or source-owner branches.

## Why this adds evidence

W48 measures incremental allocations with tracemalloc **inside** the test interpreter. High-water process RSS may differ because tracemalloc does not track all native allocations, allocator fragmentation, or existing process memory. W50 runs the **real, uninstalled optional** lightup.finding_markdown_escaped_optin_w31.render_escaped_evidence_markdown_optin_w31 in a fresh Linux Python interpreter per synthetic case, and measures both resource.getrusage(RUSAGE_SELF).ru_maxrss in KiB and tracemalloc incremental peak bytes.

Reproduce from the repo root (no models/API credentials, target traffic, or real evidence):

    PYTHONPATH=src python -m unittest -v tests.test_finding_markdown_isolated_rss_w50

Five methods exercise separate-process large valid escaping, output-overflow atomic refusal after line assembly starts, late-row/oversize-scalar/duplicate preflight refusal before any escape, empty/Unicode controls and identical SHA-256 output across independent invocations. Every subprocess checks exact exception type/message, no returned partial artifact, caller input unchanged, metadata exclusion, output bytes, and tracked memory/RSS observations. Cases use only invented strings and metadata canaries.

## Measurement limitations and release gate

- RSS after-minus-before is a **delta of high-water marks**, not a reliable measure of all temporary renderer allocations or the full process's lifetime peak.
- tracemalloc starts **after fixtures already exist** and tracks only Python-instrumented memory; it misses preexisting strings, some native allocations, system pressure and CPU bounds.
- **32 MiB Python-tracked peak** and **512 MiB Linux process RSS** are conservative diagnostic CI tripwires, not universal upper limits or customer SLAs. Each sample runs in a fresh subprocess to avoid inter-case contamination. macOS ru_maxrss has different units.
- Passing Markdown preflight is **not** a guarantee of downstream Markdown-to-HTML sanitization, math extensions, linkification, XSS protection, tenant privacy, or authorization. No Markdown-to-HTML engine is a pinned runtime dependency in the repository. Separate integration must name and pin the **actual** downstream parser/flags and independently verify resulting HTML.
- These tests neither modify installed routes nor prove latest-main compatibility, historical-record support, production coverage or verified remediation/retest.

## Required for promotion

1. Record the exact **current W50 SHA** and independently inspect completed hosted Python 3.11 + 3.14 unit and producer-integration outcomes. Superseded heads do not count.
2. Require exact-head **completed SUCCESS** on the registered permanent vps-bb300bba self-hosted runner; queued/running is not acceptable proof.
3. Obtain original #894/#100/#732 source-owner signoff, installed Markdown-to-HTML privacy/security review, safe current-main composition, and explicit human approval before merge/deploy.

**DRAFT/HOLD/NO MERGE/NO DEPLOY.** No client, outside target, scanner, authorization grant, executed fix, actual retest or production change.
