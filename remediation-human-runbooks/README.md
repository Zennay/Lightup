# LightUp · PRIVATE HUMAN Remediation Runbooks

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This independent offline application prepares human coordination. It does not authorize an assessment, remediation, retest, verified security verdict or production deployment.

## Open the product

[Open the standalone offline editor](standalone.html) or save this single HTML file and open it locally. No installation, server, network access, credentials, scanning, browser persistence, remote resources or model call.

1. Export the **complete** original source-bound PRIVATE HUMAN workplan JSON from [draft Evidence Handoff Inbox #1644](https://github.com/Zennay/Lightup/pull/1644). Do not substitute individual owner packets or an unbound CSV.
2. Import the full original JSON (1 MiB limit, up to 350 findings). The editor enforces its original v1 shape, all twelve authority flags literally false, exact source SHA/client/engagement labels and complete original finding-ID membership.
3. Select an original finding and write up to eight sequential human discussion steps, naming proposed human follow-ups, self-declared owner, tentative date, prerequisites, rollback discussion and independent-review questions. Filter unplanned, blocked or handoff-prepared work.
4. Download a complete PRIVATE source-bound JSON backup. Optionally export one selected original finding to a confidential, scriptless PRIVATE HTML human briefing, or only grouped anonymous human-stage counts CSV.
5. Restore a previously saved PRIVATE JSON (max 8 MiB; original input remains max 1 MiB) against **the identical full original finding set and source binding**. No partial migration or silent mixing of sources is performed. Replacement requires explicit confirmation.

## Owner-specific human handoffs

After assigning self-declared human owners to individual proposed steps, choose an alias in the recipient menu. Export **only** that owner's steps across original findings as PRIVATE JSON, or download a scriptless, HTML-escaped, printable **one-owner readable briefing**. These packets omit other owners' proposed steps, original private workplan notes, and raw evidence. Neither export verifies the recipient, source, fix, consent or grant; use a separately authenticated confidential human channel. Preserve the full PRIVATE runbook JSON independently as a backup: owner packets are intentionally partial handoffs, not restorable full runbooks.

Full PRIVATE runbooks can exceed the 1 MiB *original source* import ceiling. The standalone editor now permits up to **8 MiB only for exact-schema PRIVATE runbook restore**, with source ID membership and source digest checks unchanged. Full exported files exceeding the allowed restore cap are refused at creation rather than producing an unusable backup.

## Safe original HUMAN context refresh

An operator may re-export the complete original workplan from the existing #1644 app after human owners, stages or private follow-up notes have changed. Reimporting it with the **same exact declared original source contract/SHA/client/engagement and complete original finding IDs** asks explicitly whether to **retain all independently authored PRIVATE runbook steps** while refreshing the read-only original human context. A different source binding instead requires the usual discard warning and starts a clean workspace; there is no cross-source migration or implicit preservation. Either accepted source refresh clears any pending reviewer merge preview and undo, and marks refreshed private steps as unsaved to encourage a current backup.

New steps initially show the original record's **self-declared HUMAN owner alias** as an editable convenience. Neither that alias nor an identical source digest authenticates a recipient, finding or permission. Manually confirm each human recipient and use separate authenticated private delivery.

## Explicit PRIVATE HUMAN reviewer collaboration

Load the **same complete original workplan** before importing another reviewer's full PRIVATE runbook backup (up to 8 MiB). The editor requires exact declared source contract/SHA/client/engagement, identical full original finding IDs and ordering, bounded canonical per-finding steps, and all 12 false authority flags. It does not infer that the source or reviewer is authenticated.

Choose **Preview exact-source HUMAN differences**. An empty incoming runbook cannot erase existing local human notes. A new nonempty runbook for an originally empty local finding is proposed as an incoming change; competing nonempty per-finding plans display both original finding ID and existing/proposed steps. Every conflict requires an explicit **KEEP current local** or **APPLY other reviewer** decision. No silent overwrite is permitted. A single explicit confirmation applies only accepted HUMAN planning changes, with a guarded Undo available until another local edit. Changing the private source, selected file or local revision after preview causes a HOLD instead.

Unlike an original owner reply, this reviewer's private runbook is just optional local HUMAN planning. It neither authenticates an original finding, verifies a fix, nor changes Casework, Evidence Review, source owner packets, grants, assessment runs or client/operator consent.

## Source and privacy contract

This tool does not authenticate the imported client, recipient, source SHA or exported document. Matching declared source metadata protects from accidental mixing but is NOT proof of authorization. Verify origin, recipient and actual client/operator consent through a separate trusted, authenticated workflow.

Duplicate JSON member keys (including escaped aliases), unexpected fields, missing or duplicate findings, noncanonical step shapes, unsupported stage values, malformed dates, invalid UTF-8 and any non-false authority flag are rejected. Source entries are displayed only as text, not injected into HTML. Scriptless HTML output escapes all imported/user-proposed text, explicitly blocks active content and must be shared privately. There is no localStorage, IndexedDB, service worker, network request or automatic save. All downloaded files are the operator's private responsibility.

Human steps are **proposals**, never commands, approval, a verified rollback plan, completed fixes, or authority to retest. An anonymous CSV excludes client/source metadata, exact IDs, names and individual details, but very small cohorts can reveal patterns.

## Ownership and release HOLD

Only new paths under remediation-human-runbooks/ on an isolated branch; no changes to the source owners of #1642/#1643/#1644, original LightUp runtime, scan, model, grants, CI, QA, tests or shared paths. Its role is ordered technical *human planning*, different from original issue-level owner/stage annotation.

Mandatory original exact-head hosted and permanently named self-hosted VPS CI, source-owner acceptance, independent security/privacy review, #177/#182/#829, true separate authenticated client/operator consent with action-time revocation and explicit HUMAN GO are still required before any main integration or deployment. No production readiness or passing gate is asserted.

Single-file HTML now embeds CSS and JavaScript whose **exact UTF-8 bytes are individually pinned by SHA-256 Content Security Policy hashes**, with default-src none, connect-src none, no form targets and no external resources. These source hashes prevent accidental inline-script/style drift; they do **not** authenticate a GitHub publisher, original customer source, user, scope or consent, and are not a substitute for independent privacy/security source review. No source-supplied string enters innerHTML or executable script.
