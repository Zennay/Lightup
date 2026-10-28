# LightUp · PRIVATE HUMAN Remediation Runbooks

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This independent offline application prepares human coordination. It does not authorize an assessment, remediation, retest, verified security verdict or production deployment.

## Open the product

[Open the standalone offline editor](standalone.html) or save this single HTML file and open it locally. No installation, server, network access, credentials, scanning, browser persistence, remote resources or model call.

1. Export the **complete** original source-bound PRIVATE HUMAN workplan JSON from [draft Evidence Handoff Inbox #1644](https://github.com/Zennay/Lightup/pull/1644). Do not substitute individual owner packets or an unbound CSV.
2. Import the full original JSON (1 MiB limit, up to 350 findings). The editor enforces its original v1 shape, all twelve authority flags literally false, exact source SHA/client/engagement labels and complete original finding-ID membership.
3. Select an original finding and write up to eight sequential human discussion steps, naming proposed human follow-ups, self-declared owner, tentative date, prerequisites, rollback discussion and independent-review questions. Filter unplanned, blocked or handoff-prepared work.
4. Download a complete PRIVATE source-bound JSON backup. Optionally export one selected original finding to a confidential, scriptless PRIVATE HTML human briefing, or only grouped anonymous human-stage counts CSV.
5. Restore a previously saved PRIVATE JSON (max 8 MiB; original input remains max 1 MiB) against **the identical full original finding set and source binding**. No partial migration or silent mixing of sources is performed. Replacement requires explicit confirmation.

## NEW — complete one-owner HUMAN receipt → response → operator review

[Open the ready-to-save standalone PRIVATE HUMAN Owner Return app](owner-return.html) alongside the [original runbook editor](standalone.html). Download/save **both files into the same private local folder** if you want the editor's relative offline link to work. The owner app itself is fully self-contained; it does not read the original full-workplan backup or any other owner's private packet.

1. **Operator (main editor):** select one declared human owner and export **PRIVATE one-owner HUMAN runbooks JSON**. Only steps assigned to that alias are included across the relevant original findings; other owners' work and the original source's private notes are deliberately excluded. Use a separately authenticated confidential channel for transfer.
2. **Recipient (owner-return.html):** independently verify the human sender, owner identity and permitted recipient out of band. Load the received packet, view the **original proposed** steps including prerequisites, declared rollback discussion and human review questions, and locally select *unverified HUMAN* response states: not responded, received, clarification needed, or discussion prepared. Add private follow-up question/notes and a tentative date. The app never performs the proposed steps, changes findings, or calls the scanner.
3. **Recipient:** download **PRIVATE owner HUMAN return JSON**, preserving a complete immutable snapshot of every original handed-off step and its source-declared SHA/client/engagement plus all 12 literally false authority flags. Optional **scriptless PRIVATE human response HTML** or privacy-minimal stage counts CSV are available. The source packet is not replaced, and browser memory is cleared by Forget.
4. **Operator (same owner-return.html):** first open the exact original one-owner handoff issued in step 1, then choose the separately received PRIVATE return packet and click **Inspect returned HUMAN answers**. The operator gets a readable finding-by-finding human response brief **only if** every exact original finding/step, original proposed text and metadata, source binding and false-only authority contract match. Missing, reordered or mutated original steps **HOLD**; no partial import or silent acceptance. This read-only comparison cannot update the main Runbook Editor, original Casework, Evidence Ledger, #1643 owner response register or client security status.
5. **Operator:** download the private scriptless review brief or human-only aggregate. Decide externally whether further human discussion is needed. The local operator's original plan, authentication state and external permission gates are never updated by a response.

This new return format (`lightup.private_human_owner_runbook_return` v1) is **distinct** from the original independently owned #1643 human evidence owner-reply packets. Never present it as an original authenticated owner reply, evidence of a verified fix, a grant, customer consent, or an approved change. All identities and permissions remain **unverified**.

**Maintainable source:** [owner-return.js](owner-return.js), [owner-return.css](owner-return.css), [owner-return.template.html](owner-return.template.html), and [build_owner_return.py](build_owner_return.py) are separate new-only files under this team's own directory. The Python standard-library-only packager recreates owner-return.html with exact SHA-256 CSP pins for the embedded JS and CSS. It is *not* a test runner, CI substitute, external service or release gate. The standalone published file is ready for local use without Python.

## NEW — unified, exact-current multi-owner HUMAN return inbox

The original [Runbook Editor](standalone.html) now has section **5 · Combined read-only HUMAN owner-return desk**. It accepts multiple independently received PRIVATE HUMAN owner-return JSON files generated by [owner-return.html](owner-return.html) without opening separate operator browser tabs for every owner.

1. First import the original full PRIVATE source-bound finding workplan and (optionally) restore the operator's complete authored HUMAN runbooks. Every received owner packet is checked **against these exact current local authored original steps**, not merely against a self-declared SHA.
2. Receive a one-owner PRIVATE HUMAN return through an authenticated confidential channel. Choose it in the combined desk and click **Add exact-source HUMAN reply**. Strict original source contract/SHA/client/engagement, complete current original finding ID membership, exact currently exported step snapshots, unique step ordinals, all 12 false authority flags, no duplicate JSON keys, bounded original source, and canonical reply-only annotations must all agree. The UI refuses stale, changed, foreign-owner, incomplete or ambiguous packets in full.
3. You may import additional **different self-declared human owners** into the same in-memory read-only dashboard. Each is displayed with original finding ID, exact step number, original proposed human work, unverified human acknowledgement, private comment and tentative human follow-up. Filter requests for clarification, unanswered, receipt acknowledged and human discussion prepared; select **Open original HUMAN finding** to navigate directly to the source-local runbook.
4. The combined dashboard also shows the **complete locally self-declared HUMAN owner coverage**: owners with no reply packet, expected original step counts, HUMAN-only acknowledgements and requested clarifications. This is visible immediately after opening the original workplan, not just after receiving a first packet. Export **anonymous team HUMAN response coverage counts CSV** without owner aliases, original finding IDs, client/source digests, notes or dates. Counts are not verified remediation or authorization evidence.
5. Imported returns are **ephemeral, read-only** and are not added to the complete backup JSON or source-owner Evidence Ledger. Editing any original runbook step, changing/refeshing the original source, restoring another plan, or performing a reviewer-merge invalidates and clears all previously imported returns. The user must re-import responses against the current exact authored step snapshot.
6. **Forget all received PRIVATE replies** clears their on-page sensitive information without deleting locally authored steps. The main Forget action clears everything. Previously downloaded private files remain under the operator's responsibility.

No imported owner response can authenticate the sender, promote any finding into a verified fix, approve a live retest, change original evidence, write to the independently owned #1643 response register, or grant current customer/operator consent. The original main draft, current issues and mandatory release HOLD remain separate.

## NEW — bulk HUMAN follow-up planning and one-coordinator PRIVATE handoffs

When owner-return packets have been imported in the main offline editor's section 5, the **HUMAN follow-up action register** in section 6 supports coordinated triage across multiple exact-original findings and owner-return steps.

**Batch human coordination:** Filter original HUMAN actions, select individual rows or all *currently filtered* steps, then propose one HUMAN-only status, optional locally declared coordinator alias, and optional tentative date. A blank coordinator/date retains each step's current assignment. The full selection is source-checked and previewed in an explicit confirmation before any local annotation changes. Existing PRIVATE notes and individually authored next actions are **preserved**. The last batch can be undone until a later action edit, incoming owner reply or source transition. This does not contact any coordinator, create a grant or prove a fix.

**Recipient-minimized confidential briefing:** Select one locally declared coordinator from the drop-down after assigning coordinator aliases. The **PRIVATE one-coordinator HUMAN HTML** contains only human follow-up steps assigned to that alias, original finding IDs, self-declared owner reply stage, local next action, tentative date and private note. Other coordinators' actions and private notes are excluded. The generated HTML is scriptless, networkless and HTML escaped; the recipient, customer source and permission still require independent authentication and private delivery.

The app's maintainable `editor.js`, `editor.css`, `editor.template.html` and Python-standard-library-only `build_editor.py` reproduce the exact standalone offline HTML with source-byte-bound SHA-256 CSP script/style hashes. The standalone artifact remains usable without Python, a server, login or network connection. Packaging is not QA, test evidence, owner authentication or a deployment.

## NEW — source-bound PRIVATE HUMAN operator follow-up register

After receiving one or more original-source-matched owner returns in the **Combined HUMAN Owner Return Desk** (section 5 of [standalone.html](standalone.html)), section **6 · PRIVATE HUMAN follow-up action register** appears. Every displayed row is tied to the **current exact original finding ID, step ordinal, self-declared owner and unverified owner reply**, not merely to a client name or source SHA.

The operator can assign only HUMAN planning annotations: untriaged; needs human input; human contact planned; human review prepared; human discussion closed (**not** a verified fix); a separately declared local coordinator; a tentative human follow-up date; next human action and private operator note. Search/filter on local human annotations and show tentatively overdue dates. These dates are NEVER actual authorization, grant, scan or execution windows.

Save the **full PRIVATE HUMAN follow-up JSON** to an approved confidential device. Its complete original IDs, exact current one-owner-return snapshots, source binding and all twelve literal false authority flags are included to prevent casual cross-source mixing. After loading the identical original workplan and the identical full set of original owner return packets again, **Restore** uses strict bounded atomic import to match every row and snapshot exactly before asking permission to replace annotations. Changed, missing, foreign or reordered replies HOLD rather than silently transferring human coordinator notes. The full JSON can be up to 8 MiB. It includes PRIVATE identifying material and human notes, and it is NOT suitable for public issue attachments.

For human coordination there is also a **scriptless HTML discussion agenda** with only locally triaged steps (still confidential, HTML escaped, no active resources), and a **counts-only CSV** free of original IDs, names, clients, source hashes, notes and dates. Tiny cohorts may still disclose information. The human-only stage of "discussion closed" says absolutely nothing about whether the original security problem is fixed.

Unsaved operator annotations trigger a browser-leave warning and a confirm-before-discard warning on relevant original step edits, source switching, plan restoration, or reviewer merge. Original step edits invalidate previously imported owner returns and human follow-up notes. Importing an updated owner return for an existing alias discards only that alias's stale operator notes after a warning for unsaved data, while preserving other owners' local work. Downloaded files are never silently altered, and nothing is persisted in browser storage.

### Limits and boundaries

The tool **cannot independently authenticate** the original owner, a customer asset, current scope, consent, human reply or remediation; it never issues authority, performs a scan, sends a message or changes a security verdict. The unverified source owner's original Evidence Artifact Ledger, Casework and #1643 evidence reply owner are untouched. Use authenticated private human channels for any external exchange; source SHA agreement is not identity verification.

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
