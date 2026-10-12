# W47 opt-in Markdown allocation characterization — issue #1221

Parent: W46 draft #1219 exact `c5b19458e2417d8bccac802ce4809c3332c579e0`.

## Scope
A tests-only, synthetic and uninstalled diagnostic harness for `render_escaped_evidence_markdown_optin_w31`. It does not change the default renderer, persisted findings, web routes, authorization or target interaction. No real client data.

## Reproduce
```sh
PYTHONPATH=src python -m unittest -v tests.test_finding_markdown_allocation_w47
```

Five cases characterize: near-limit escaped references, 8,192 distinct references, oversized source early denial, later-row atomic denial, and Unicode/empty controls. Python `tracemalloc` measures Python-tracked peak allocations only; it excludes some native allocations and does not establish a hard RSS, CPU, time, or HTML-renderer bound. The provisional 32 MiB threshold is a lab regression tripwire, not a security guarantee or production limit.

## Required follow-up before acceptance
- Run this exact branch on both Python 3.11 and 3.14, capture logs, failures and peak metrics; adjust only if justified by observed baseline, not to hide regressions.
- Independently inspect the real Markdown-to-HTML engine, sanitization, links, redaction and renderer-specific escaping. A Markdown escape is not an HTML security proof.
- Validate exact-head permanent self-hosted VPS CI, current-main compatibility and review by original #894/#100/#732 source owners and privacy/security owners.
- Retain **Incubate M3/M7 PLAN/LAB; DRAFT/HOLD/NO MERGE/NO DEPLOY** until explicit approval.
