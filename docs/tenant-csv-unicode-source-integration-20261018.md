# Tenant finding CSV: guarded export integration · 18 October 2026

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No main merge or deploy.

## Shipped candidate behavior
The real `render_client_findings_csv(store, ctx, client_id, engagement_id=...)` tenant selection service now hands its already-authorized, canonical original `Finding` objects to `render_findings_csv_checked` from prior exact source [#1195](https://github.com/Zennay/Lightup/pull/1195), rather than the unguarded renderer.

The source validator inspects the **entire** batch before rendering and rejects malformed enum/identity/text shapes, over-budget/oversized batches, Unicode hidden/compatibility prefixes and ambiguous presentation identities. Original service still performs tenant and engagement lineage checks *before* the renderer. Valid batches preserve the existing columns, redaction and ASCII apostrophe formula neutralization. Invalid later records result in an error rather than a partially serialized CSV.

This changes the **normal authenticated tenant CSV service** and its existing entrypoints, not just an optional helper script. The low-level legacy `render_findings_csv` remains unchanged; direct internal users of that renderer are not automatically guarded. The guard does not certify spreadsheet engine safety or complete credential redaction.

## Ownership, limits, release
- New branch descends from the immutable prior guarded source [#1195](https://github.com/Zennay/Lightup/pull/1195), commit `8ef5534d8520df30f6ae50a1114912ceb3a9eba8`. It does not alter that original owner branch or its tests.
- Changed product source: `src/lightup/finding_export_service.py`, plus this new integration note. Original domain, selection, web auth, scanner, consent/grants, CI/workflows, and tests untouched.
- No QA/regression suite authored, extended or run; no findings created; no real data exported; no target, model, handler, scan, grant or deployed service accessed.
- Independent owner/privacy/security review, latest-main integration with original hosted + permanently registered VPS exact-head CI, genuine separate client/operator consent and at-use revocation for any active assessments, and explicit HUMAN GO remain mandatory.
