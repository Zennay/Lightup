# W13 — checked CSV pre-render session admission (expected RED)

- Existing issue: #1197; source-owner draft: #1198.
- Base: `bda8381857cc6767e1675e711c48e46b507f6864` (W11).
- QA test commit: `2836380e91c3c11ce4bbaa7530d48e0571e9b118`.
- Added test: `tests/test_finding_export_checked_wsgi_prerender_identity_20261011_w13.py` (72 lines, four cases).
- Tests require that a mismatched identity, unknown session, or revoked session cannot invoke the tenant CSV renderer. A matching live session remains a positive control.
- Source-owner observation: current opt-in `CheckedFindingExportWebApp.download_findings` checks token presence, renders, and only then rechecks persisted identity. A pre-render session-context check should precede renderer invocation while preserving the post-render check.
- Validation: local `python -m py_compile` PASS on the QA file. Previous isolated probe: 5/7 baseline failures; hypothetical pre-render guard 7/7 PASS. These isolated results are **not** exact-head full repository CI.
- W13 PR creation was denied; no W13 CI run, merge, deployment, or production acceptance. Permanent W11 self-hosted CI run #38110542050 remained queued at inspection. No source-owner or default application file modified.
- **M3/M7 PLAN/LAB only.** Synthetic disposable SQLite only; no customer or target activity, grant, active testing or authorized deployment.

## Fresh isolated W11 decision-order probe (2026-10-11)

Replayed the exact W11 handler decision order with mocked store, renderer and response dependencies (not full repo/WSGI): **baseline 1/4 passed**, with three denied invalid sessions still invoking renderer; adding a local-only pre-render session lookup gave **4/4 passed**, including the valid-session positive control. Local artifact: `lightup_qa_1540/probe.log`; this is NOT hosted/permanent CI or an integrated source fix. Test-only GitHub head remains held for source-owner adoption.
