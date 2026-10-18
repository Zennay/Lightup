# LightUp · Original Request Binding History Desk

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD. This is a privacy-conscious offline review tool, not a grant, consent validator, operational security scan, revocation, or release decision.**

## User-visible capability

Open [standalone.html](standalone.html) as a local file in a browser; no server or build step. Select **2–12 original PRIVATE JSON files** produced by the independently owned, authenticated [Request Binding Readiness Desk PR #1590](https://github.com/Zennay/Lightup/pull/1590), always for the **same exact proposed engagement/scope/risk**. The original source owner's [#1570](https://github.com/Zennay/Lightup/pull/1570) request/grant predicate is not reproduced or changed here. The app does not authenticate the operator itself or touch the original database.

The product reads only the original single-selection `lightup.request_binding_preparation.v1` JSON format. Multi-scenario `lightup.request_binding_scenarios_review.v1` reports are intentionally **refused** rather than silently flattened to a misleading timeline. Select `.json` when exporting from PR #1590 (not `.html` or an anonymized `.csv`).

### Results

- Source-reported administrative candidate counts, unapproved and incompatible requests, historical stored grant counts and legacy unbound grant counts for each chosen file slot.
- **Original mismatch-reason trajectory:** a per-slot table for the exact seven source-owner reason codes (approval missing, mode, role/tenant provenance, risk, asset subset, decision chronology and residual source-owner integrity checks), with fixed human follow-up routing and explicitly non-chronological deltas. Aggregate JSON and CSV retain counts and original fixed reason codes but never individual request identities.
- Revision-change and count deltas between adjacent files selected by the human. *A different stored-source hash means at least one originally exported source record differed, not which record, which actor changed it, or whether a grant was revoked.* Same unsigned digest is not a live-state guarantee either. Files may be deliberately reordered; selection order is **not verified chronology**.
- Built-in human-only follow-up checklist. Export aggregate JSON/CSV without source fingerprints, file names, client/asset/request identities, or private notes. Print a local brief.
- Optional PRIVATE stage-resume JSON: uses WebCrypto SHA-256 of the full original raw JSON **byte sequence** for every selected file in its original order. Restoration rejects changed source files or order and never imports earlier local stages against different source inputs. The hash is local integrity, not an authenticated signature.

### Strict input boundaries

Import is **atomic**, bounded to 12 files of <=2,000,000 bytes each and <=12,000,000 bytes total. The parser rejects duplicate JSON keys (including escaped equivalents), invalid JSON/escaping, nonfinite JSON numbers, deep/complex input and trailing data. Original source format, original PR-1570 owner label, original five literal `false` authority flags, exact 64-digit unsigned source/selection digests, canonical status/disposition, candidate counters, unique pseudonymous row labels, exactly seven original source-owner reason codes, original reason totals and summary consistency must agree. A failed import leaves the prior accepted workspace and human stages intact. No network requests, browser persistence, cookies, analytics, external CSS/scripts, credential handling, target access or mutation.

Scope-selection equality is an **unsigned locally recomputed selection digest claimed by each input**, not verified tenant, actor or permission. Original operator reports may be stale, tampered with or generated from divergent feature branches. A comparison is always informational only.

### Fictional UX examples

To inspect display flows without opening any private data, select [fictional-a.json](fictional-a.json) and [fictional-b.json](fictional-b.json) together. Both are entirely **invented demonstration material** with dummy revision fingerprints, not authentic operator exports or source-state evidence. Do **not** include them with actual exports or claim they prove original revision changes.

## Scope isolation and safety

This independent new directory does **not** alter PR #1590, PR #1570, scope/grant domain, web authorization, readiness/portfolio PR #1569/#1588, CI or runner. All five authority flags stay false. A stored approved request and compatible candidate do not constitute true independent client+operator consent or permission to scan. Preserve existing independent privacy/security review, consent with action-time revocation, source-owner acceptance, exact-head hosted and permanent named VPS CI, and explicit HUMAN GO. Do not merge/deploy/issue grants/dispatch/run target tools from this DRAFT/HOLD branch.

No QA, regression or testsuites are created or executed. An ordinary source syntax/markup inspection is sufficient for this isolated browser-only delivery; it cannot demonstrate authenticated production behavior.
