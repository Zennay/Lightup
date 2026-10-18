# LightUp · Private Lab Review Desk

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Isolated browser-only companion to the **unchanged** original multi-endpoint lab assessment in [draft #1610](https://github.com/Zennay/Lightup/pull/1610), pinned source 74e865201c8a4270e404046ef3447eb7f190edfb. Tracks [#1637](https://github.com/Zennay/Lightup/issues/1637).

## Open immediately

Open **[standalone.html](standalone.html)** as a local file. It is one complete HTML file with inline JavaScript/CSS and SHA-256 Content Security Policy (connect-src 'none'). The editable source is index.html + app.js + style.css. Rebuild the portable file with the standard-library command: **python3 assessment-lab-review/build_standalone.py**.

1. Select an existing PRIVATE result JSON produced by the original, separately held lab-assess --output command. This app **never** runs it. Do not create a new lab result on someone else's assets.
2. The browser admits the bounded original source structure **all-or-nothing** (1–16 declared target strings, ≤2048 unique original findings, exact finding fields, no duplicate JSON properties, mandatory original lab context when a benchmark case is present). The private queue shows original finding severity, local endpoint ordinal and human-readable source text; evidence summaries are only in expandable private panels.
3. For each original finding, propose a human-only review stage, generic reviewer group, next action and uncertainty/blocker. Filter by original severity or human stage. These do **not** change original evidence, findings, retests, authorization or client state.
4. Save **PRIVATE human review**. It contains an unsigned source-byte SHA-256, anonymous original finding ordinals and bounded human notes with explicit literal-false authority. Reopen the original PRIVATE file and separately restore the PRIVATE notes later. A changed or reordered source refuses the entire restoration before current notes change.
5. Alternatively export counts-only JSON: declared endpoint/finding/severity totals and human stage/group totals. It contains **no targets, file paths, finding IDs, raw evidence, names or original hashes**. Small aggregates can still be sensitive and should only be shared after separate human review.
6. Use **Forget all local data** to discard the in-memory source. There are no accounts, trackers, cookies, localStorage, service workers, external fonts, fetches, DNS, models, scanners, workers or grants.

## Source/privacy boundaries

* File input is explicit local browser selection, capped at 8 MiB, with fatal UTF-8 decoding and strict duplicate-key JSON parsing. Source errors and invalid returns never partially apply.
* Human review returns have fixed keys, enumerated stages/groups and limited free text. Source bytes are **never** copied to a return, and output only occurs via a human-initiated download.
* Browser-local file inputs cannot enforce Unix no-follow or filesystem mode rules. The original separate lab-inspect CLI is the source owner’s private file admission path. This browser only handles a deliberately opened file; it cannot establish authenticity.
* A source-provided benchmark_case must declare is_lab true, authorization null and the same run_id. This is an untrusted structural declaration, **not proof** of lab isolation or permission.
* Previews and standalone record/context benchmark envelopes are intentionally rejected; they have no finding-by-finding review semantics.
* Source-provided severities, retest state, evidence summaries, original targets and even source hash are **not independently verified facts**. Missing source findings are never automatically repaired. Edits only affect local human notes and not the source.
* Human notes remain in memory unless deliberately exported. Unsaved changes trigger a browser leave warning. Use an appropriately protected offline channel for any PRIVATE file.

## Release conditions

**NO MAIN MERGE, LIVE DEPLOY, TARGET EXECUTION, GRANT OR CLIENT APPROVAL.** Exact-head hosted and permanently registered named VPS CI, original owner acceptance, independent security and privacy, authentic independently authenticated client/operator consent and action-time revocation, #177/#182/#829 and explicit HUMAN GO remain mandatory. No QA/regression/testsuites added or run; syntax and static bundling only.
