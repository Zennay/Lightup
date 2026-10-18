# LightUp · PRIVATE HUMAN Response Reconciliation

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No execution or release authority.**

This standalone **offline, multi-owner HUMAN follow-up register** is a read-only companion to the original source-owning [Evidence Artifact Ledger, draft PR #1642](https://github.com/Zennay/Lightup/pull/1642), pinned to source HEAD `6a8cd3baf6535705a7baca77dc3dc5067f862b3d`. All files are new under `remediation-response-reconciliation/`. It does **not** change that PR, the original five-field source parser, Casework, Evidence Review, scanners, consent, grants, active targets, or production.

## Portable offline product (published)

- [Open the self-contained offline HTML](standalone.html) — one file, all JS/CSS included, no network dependencies, deterministic script/style SHA-256 CSP pinning.
- [Open the three-file development version](index.html) with local `app.js` and `style.css` alongside it.
- Rebuild after source changes with `python3 build_standalone.py`; `python3 build_standalone.py --check` confirms the exact committed bundle. These are build/integrity commands, not QA suites. Do not assert a VPS build unless actually executed by the permitted runner/zSSH.

## Human review & team operations

- Each original request now has a **PRIVATE details expander** showing its exact original request identifier, locally declared owner and issued timestamp, full original instructions, the entire received HUMAN reply text, and its unverified status. Viewing a reply does not verify the sender, source or remediation.
- Filter by local human stages, upcoming tentative dates (within seven UTC days), tentatively overdue dates, unplanned work, source original ID, request kind or alias. Sort by original packet, date, alias or local human status. These are **planning hints only**, never execution windows, SLAs or authenticated identities.
- Select exact original request IDs individually or select **all rows in the current filter**. Selections can span filter views; the explicit preview displays original finding IDs, full request IDs, self-declared owners and old → proposed HUMAN-only stages before a separate confirmation. A changed original register, selected ID set or local HUMAN baseline invalidates application. The **last HUMAN bulk change** can be undone while the exact local source/review revision remains unchanged; subsequent independent local edits invalidate that undo instead of silently reverting later work. A distinct selected-only PRIVATE action brief exports just the deliberately selected original finding/request IDs, HUMAN instructions/replies and human follow-up notes with all security authority flags false. It is a manual operator handoff, not an original owner-reply packet.
- The standalone **anonymous aggregate counts CSV** contains only HUMAN request type, unverified reply stage, local review stage and count. It does not contain original finding/request IDs, aliases, source SHA, response bodies, evidence fingerprints, targets or client context. The original PRIVATE per-ID CSV is separate with its own acknowledgement.
- The **PRIVATE owner-specific HUMAN review brief JSON** exports only one self-declared owner’s exact source-bound original request ID, finding ID, original HUMAN instructions and tentative date, any received unverified answer, local HUMAN status and private follow-up note. It excludes every other owner. The recipient and transport must be verified independently; it is NOT an original owner-reply packet, not accepted by the original owner app, and not proof of identity, remediation, retest or grant.
- The full PRIVATE workspace restore supports up to **8 MiB** for large human registers; exact native original owner request/reply files remain at **1 MiB** each, with fatal UTF-8 decoding and duplicate-key rejection.

## Workflow

1. Open `index.html` with `app.js` and `style.css` alongside it, without an internet connection. No credentials, server, account, installation or internet access required.
2. In the original evidence ledger, export PRIVATE *owner-specific human request* packets (up to 60 requests per page). Owners use its separate standalone reply page to save **partial** unverified response packets to their own device. Exchange both through a separately approved/identity-verified PRIVATE human channel.
3. Import one or multiple original packets together. The register binds all imports to the **exact original source SHA-256 + declared client + declared engagement**, checks exact v1 original packet schemas, requires all twelve authority flags to be `false`, and rejects duplicate JSON keys, unknown fields, mixed engagements, missing original requests, mutated request instructions and conflicting partial replies. It stages imports atomically before replacing in-memory state. Original packets are never modified.
4. Filter unanswered, unverified responses, requests needing changes and items awaiting **local HUMAN triage**. Add only local reviewer stage and follow-up note (400 characters per request); triaging does not mark findings fixed or authenticate a sender.
5. Export a complete PRIVATE exact-source-bound register JSON for resuming work, a separately acknowledged formula-guarded PRIVATE CSV, or a scriptless PRIVATE print brief. Restore the register from its own JSON alone, explicitly replacing current memory. Click **Forget** to clear in-memory data (not previously downloaded files).

### Deliberately strict handling

- 1 MiB max per original owner JSON and 8 MiB max per own register backup; 24 packets and 800 unique original human requests max. Imports use fatal UTF-8 decoding and bounded duplicate-key rejecting parsing, and no browser storage.
- Original source SHA, client and engagement are **declarations** from imported files, not cryptographic authentication or verified tenant identity. An SHA-256 string alone does not prove provenance.
- A reply stage of `submitted_unverified` / `needs_changes` is **human-supplied text**, not a verified fix or approved retest.
- Duplicate requests in different owner packets, altered owner-request baselines, and conflicting replies HOLD the whole import instead of selecting one.
- Separate owner packets sharing an identical original binding may be reconciled; multiple independent sources/engagements may not.
- This app does not send messages, open targets, call APIs, store cookies, access network, issue permissions, validate findings, scan or retest. CSS/JS loaded locally only. Do not treat local exports as approvals.

## Operator safety & future integration

The original source-owning evidence ledger and this companion must remain separate until its owner reviews the exact dependent PR. Release remains blocked by original exact-head hosted **and permanently registered named VPS** CI, original source-owner and independent security/privacy review, genuine separately authenticated current client/operator consent with action-time revocation, #177/#182/#829, and explicit HUMAN GO. No security/permission gates may be bypassed. No QA or regression suites are introduced by this companion.

**Branch:** `chatgpt/lightup-remediation-response-reconciliation-20261018` based on original pinned owner HEAD. Offline preparation only. No live targets, current grants or activation.
