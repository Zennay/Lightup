# LightUp · Browser-first Private Human Capacity Studio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** An **interactive, private and fully offline** companion to [the multi-agenda portfolio](README.md) and [capacity CLI](CAPACITY.md), not an assessment executor or an authorization tool.

## Open a complete local editable planning view

Use the *unchanged* original `assessment-archive/agenda.py --format json` exports; do not prepare artificial consent, grants or client IDs.

```sh
python3 assessment-portfolio/browser_studio.py \
  --agenda /private/original-a-agenda.json \
  --agenda /private/original-b-agenda.json \
  --as-of 2026-10-18 \
  --output /private/NEW-human-capacity-studio.html
```

Open the **owner-private HTML file** directly in the browser with no local server. It contains:

- Original offline follow-up slots from 1–12 original separately completed private agenda files, bound to their SHA-256 source bytes at creation (the digests are private correlation references, *not issuer authentication*).
- Interactive per-role hypothetical weekly human review touchpoint budgets (0–100), chosen 1–12-week planning horizon and role filter. No reviewer, task, scheduling or authority mutation.
- Recomputed queue order: originally proposed past dates, reference day, future dates and unscheduled, then original stage and stable agenda/source slot.
- A live role coverage matrix and a live visible **without a hypothetical slot** queue. Original HOLD is always shown alongside its rows and is never removed by increasing capacity.
- Explicit, user-initiated anonymous aggregate-only JSON export (no original client findings, source slots, SHA hashes, reviewer names, source targets or exact original proposed dates). This is not a client security report.

The program parses the full private original agendas with the same **no-follow original bounded reader, duplicate-key-safe decoder, strict schema/count/date/role checks and false-only authority constraints** as the non-interactive portfolio. It embeds only a normalized source subset inside a **CSP-SHA256-locked** self-contained HTML file; no external assets, browser storage, cookies, telemetry, uploads, APIs, target access, grants or workers. Rendered original values use DOM `textContent`, not interpreted HTML; inert source JSON escapes HTML terminators. The CSS and JS are static repository sources bundled into the delivered artifact.

**Private boundary:** Source-byte digests and original human slot IDs are still present in this HTML to enable local traceability. Treat the complete Studio as private. The anonymized aggregate may still disclose small-team workload; review it before sending.

Exit 2 = original-source human review only; 3 = retained original HOLD or rejected input. No exit 0 implies clearance.

No QA/regression/test suites, original scanner, model, login, grant, assessment run or web request is added or executed. All existing exact-head CI, privacy/security/source-owner approval, real separately authenticated client/operator consent with at-use revocation and explicit HUMAN GO remain mandatory before source integration into main or deployment.

## Saved original-source-bound human capacity presets

The self-contained capacity Studio now supports **Download PRIVATE source-bound plan** and **Restore PRIVATE source-bound plan**. All original selected agenda slot/hash/status tuples, shared date, and 1–12-week neutral role capacities must match exactly; restore is atomic in browser memory and cannot imply review assignment or authorization. A separate [saved-capacity CLI](SAVED-CAPACITY.md) reads the unchanged original PRIVATE agendas and the saved private plan to regenerate the original hypothetical HTML or anonymous aggregate reports. No browser storage or active target work is added.

## Unified review and navigation

Open `workspace-home.html` in the complete original private workspace ZIP to navigate original queue, cross-agenda human Review Studio, hypothetical capacity planner and counts-only reporting. The [cross-agenda human attention desk](CROSS-AGENDA.md) supports bounded human-only batch edits across all original agenda slots; private `--proposal-bundle` return and continued review cycles retain original source/HOLD admission and never change actual permissions.
