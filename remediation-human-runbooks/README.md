# LightUp · PRIVATE HUMAN Remediation Runbooks

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This independent offline application prepares human coordination. It does not authorize an assessment, remediation, retest, verified security verdict or production deployment.

## Open the product

[Open the standalone offline editor](standalone.html) or save this single HTML file and open it locally. No installation, server, network access, credentials, scanning, browser persistence, remote resources or model call.

1. Export the **complete** original source-bound PRIVATE HUMAN workplan JSON from [draft Evidence Handoff Inbox #1644](https://github.com/Zennay/Lightup/pull/1644). Do not substitute individual owner packets or an unbound CSV.
2. Import the full original JSON (1 MiB limit, up to 350 findings). The editor enforces its original v1 shape, all twelve authority flags literally false, exact source SHA/client/engagement labels and complete original finding-ID membership.
3. Select an original finding and write up to eight sequential human discussion steps, naming proposed human follow-ups, self-declared owner, tentative date, prerequisites, rollback discussion and independent-review questions. Filter unplanned, blocked or handoff-prepared work.
4. Download a complete PRIVATE source-bound JSON backup. Optionally export one selected original finding to a confidential, scriptless PRIVATE HTML human briefing, or only grouped anonymous human-stage counts CSV.
5. Restore a previously saved PRIVATE JSON against **the identical full original finding set and source binding**. No partial migration or silent mixing of sources is performed. Replacement requires explicit confirmation.

## Source and privacy contract

This tool does not authenticate the imported client, recipient, source SHA or exported document. Matching declared source metadata protects from accidental mixing but is NOT proof of authorization. Verify origin, recipient and actual client/operator consent through a separate trusted, authenticated workflow.

Duplicate JSON member keys (including escaped aliases), unexpected fields, missing or duplicate findings, noncanonical step shapes, unsupported stage values, malformed dates, invalid UTF-8 and any non-false authority flag are rejected. Source entries are displayed only as text, not injected into HTML. Scriptless HTML output escapes all imported/user-proposed text, explicitly blocks active content and must be shared privately. There is no localStorage, IndexedDB, service worker, network request or automatic save. All downloaded files are the operator's private responsibility.

Human steps are **proposals**, never commands, approval, a verified rollback plan, completed fixes, or authority to retest. An anonymous CSV excludes client/source metadata, exact IDs, names and individual details, but very small cohorts can reveal patterns.

## Ownership and release HOLD

Only new paths under remediation-human-runbooks/ on an isolated branch; no changes to the source owners of #1642/#1643/#1644, original LightUp runtime, scan, model, grants, CI, QA, tests or shared paths. Its role is ordered technical *human planning*, different from original issue-level owner/stage annotation.

Mandatory original exact-head hosted and permanently named self-hosted VPS CI, source-owner acceptance, independent security/privacy review, #177/#182/#829, true separate authenticated client/operator consent with action-time revocation and explicit HUMAN GO are still required before any main integration or deployment. No production readiness or passing gate is asserted.

Single-file HTML uses a static CSP nonce for its bundled source with connect-src none. It is not a secret, not provenance authentication and not a substitute for independent source review. No source-supplied string enters innerHTML or executable script.
