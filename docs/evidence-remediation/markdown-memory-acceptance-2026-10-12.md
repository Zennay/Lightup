# Markdown evidence rendering: independent memory acceptance

Status: **PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY**. Tracks #1221; does not assert completed validation.

## Threat model
Untrusted evidence fields can expand during Markdown escaping, normalization and downstream HTML conversion. A source-size cap and 2 MiB escaped-output cap do not alone bound peak process RSS, temporary line allocations or per-object overhead. No tenant authorization follows from a successful renderer preflight.

## Opt-in synthetic acceptance matrix

| Case | Required observation |
| --- | --- |
| Empty and ordinary Unicode evidence | Deterministic valid rendering; unchanged input |
| 16 KiB field and 16 KiB + 1 field | Boundary accepted/rejected per contract before normalization |
| Long escape-heavy valid text | Escaped output within 2 MiB or atomic deterministic refusal |
| Many near-limit references | Peak `tracemalloc` recorded against baseline; no partial output |
| Invalid final row after valid rows | Atomic refusal; no partial report; unchanged source |
| Markdown to HTML conversion | Independently check escaping, sanitization, redaction, and tenant-safe presentation |

## Measurement protocol
Use disposable synthetic data only. Pin exact branch SHA and Python version. Run each case in a fresh process, warm imports, collect `tracemalloc` peak and platform RSS separately, and repeat to account for allocator variance. Record input bytes, escaped bytes, case count, peak Python-tracked allocation and peak RSS. Document a conservative lab-only budget before evaluating results; do not equate `tracemalloc` with RSS or assert hard process-memory guarantees. Check exception class and exact boundary semantics, never just an error string. Preserve default renderer and owner files.

## Release evidence checklist
- [ ] Tests-only opt-in harness on immutable W46 parent, with exact commit SHA
- [ ] Normal/Unicode and adversarial boundary cases verified
- [ ] Hosted Python 3.11 and 3.14 exact-head results
- [ ] Permanent registered self-hosted VPS CI exact-head success
- [ ] Independent Markdown-to-HTML, redaction and tenant-authorization review
- [ ] Original source-owner and privacy/security signoff
- [ ] Latest-main compatibility review and explicit merge/deploy authorization

Until all gates are evidenced, retain PLAN/LAB ONLY; no live targets, customer data, active testing, remediation or retest.
