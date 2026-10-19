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

## Separate human owner-facing reader

The self-declared owner who receives a PRIVATE one-owner review brief no longer needs to inspect raw JSON. Open the [portable, source-pinned offline OWNER BRIEF READER](owner-brief-standalone.html) as a **separate read-only one-file HTML** and choose `LightUp-PRIVATE-one-owner-human-review.json` received through an **independently authenticated and approved** confidential human channel. The reader:

- Admits only the exact exported `lightup.private_human_owner_review_brief` v1 format, up to 8 MiB / 800 original unique HUMAN request IDs, with duplicate-key rejection, fatal UTF-8 decoding, exact schema, original SHA, self-declared client/engagement/recipient, and all security authority flags explicitly false.
- Displays original instructions, tentative HUMAN dates, the actual unverified owner response and the operator's human-only follow-up annotations. Filters unanswered, `needs_changes`, or `needs_human_followup` tasks. Safely treats all source text as text, never HTML.
- Can print the **entire visible PRIVATE brief** with original instructions and response details expanded. A confirmation warns the recipient to use a confidential printer or output location.
- Does not authorize execution or retests, authenticate source/recipient, edit requests, send replies, upload files, make network requests, store anything in browser storage or affect the original owner-reply app.
- Erases all in-memory source and user response data with **Forget**. Previously downloaded or printed files remain the human operator's responsibility.

Three-file development version: [`owner-brief.html`](owner-brief.html) with `owner-brief.js` and local `style.css`. Deterministic standalone source bundle: `python3 build_owner_brief.py` (or `--check`). The reader uses independently SHA-256 CSP-pinned embedded assets, `connect-src 'none'`.

## Complete source-bound HUMAN feedback return loop (v2)

The private operator→owner→operator **non-authorizing** roundtrip is now implemented, still with **no network and no original-source changes**:

1. In the operator offline register, export a **PRIVATE one-owner human review brief v2**. It includes the exact original source SHA, declared client/engagement and original owner alias, the exact request and current unverified original response baseline, and — if already accepted — the separate prior HUMAN feedback (status, note, self-declared UTC). It never exports another owner's work.
2. Open the offline [Owner Brief Reader](owner-brief-standalone.html), which supports **both historical v1 and current v2** packets. For chosen requests, draft an acknowledgement (unverified), ask for clarification, or say a human-only response cannot be provided. Clarification/unavailable requires an explanation. Draft text stays in memory and survives local search/filter updates. Export **PRIVATE owner HUMAN feedback** `lightup.private_human_owner_followup` as a separate local JSON file; this is neither a grant nor a valid original owner-reply packet.
3. In the operator offline [Response Register](standalone.html), use the separate owner feedback importer. Admission requires exact non-authorizing schema, all twelve authority flags `false`, fatal UTF-8, duplicate-key rejection, bounded 8 MiB/800 exact unique IDs, identical original source SHA/declared client/engagement, exact recipient alias, original issued UTC, finding ID/kind/instructions/tentative HUMAN due date **and unchanged original unverified response stage/text**. A mismatch **HOLDs the entire packet**.
4. Preview the exact original IDs and old→proposed HUMAN feedback. The operator confirms explicitly before atomic local application; stale local revision/source/response rejects application. **No original request, reply, finding, retest, grant or authorization is modified.** Accepted feedback is a separate unverified field. Reimporting an identical packet is idempotent; changed HUMAN feedback is an explicit new human revision and the previous version is retained as a private local history item.
5. HUMAN follow-up stages are visible separately from original reply statuses in the operator board, PRIVATE per-ID CSV, anonymous aggregate counts and owner-specific human brief. The full register JSON has **schema v2** including current feedback and prior feedback history; **legacy v1 imports still work**, but new exports use v2. Forget clears all in-memory feedback and history. Confidential exports can contain private human names, source IDs and notes, and require independent recipient/channel verification.

**Scope / release posture is unchanged:** the files are all in this PR's own offline companion path, not authentic grant issuance or original Evidence Review. No real security finding is certified, and no new permission to scan or retest exists. Do not merge or deploy until original exact-head hosted and named permanent VPS CI, original source-owner/security/privacy review, genuine current separately authenticated client and operator consent with action-time revocation, original #177/#182/#829 and explicit HUMAN GO have been satisfied.

## Private cross-reviewer workspace merge

The earlier **Load PRIVATE Register** action restores and replaces an entire local workspace. The new **Merge PRIVATE reviewer workspaces** operator panel is a separate additive HUMAN collaboration workflow:

1. Each independent HUMAN reviewer explicitly exports their own source-bound v1 or v2 register backup. An operator opens one PRIVATE register, then selects another export under **Merge PRIVATE reviewer workspaces** and chooses **Preview**. No browser storage, server, network, live targets or automatic upload is involved.
2. Both workspaces must match the **exact original immutable evidence source SHA-256, self-declared client and engagement**. Existing source-bound original owner-request and original unverified response packets are admitted only through the original strict packet parser; changed, ambiguous or reused original request IDs or different response text **HOLD the entire merge** rather than replacing originals.
3. New, independently acquired original packets can be appended. Separate local HUMAN review notes and owner HUMAN feedback are combined without overwriting existing nonblank values. When both reviewers recorded **different** HUMAN annotations on the same original request ID, the interface shows each text value side by side and requires an explicit **KEEP local** or **APPLY incoming** decision for every conflict. Missing/blank incoming reviews never erase completed local annotations.
4. Human feedback history from both source-bound registers is retained as PRIVATE non-authorizing annotations. A bounded historical record cap and exact row admission remain enforced.
5. The operator must confirm the summarized merge. Before applying, source binding, original request coverage, current local revision and selected PRIVATE import file are rechecked. If the local HUMAN register changed since the preview, the merge HOLDS. Nothing is sent or interpreted as authentic client consent, authorized scanning, verified remediation or executable permission.
6. The latest successful merge has a guarded **Undo last reviewer merge** action while no later local reviewer edit has changed the workspace revision. This restores the entire prior local work area, including all original packets and annotations present before the merge, without modifying files already downloaded to disk. Reopening/importing any other register invalidates that undo.
7. The operator's visible **UNSAVED local HUMAN workspace** marker stays lit after any local change or merge until a complete PRIVATE register JSON is exported. The browser has no persistent storage. The browser also requests a **native unsaved-data warning** on tab close/navigation after local changes. Browser implementations may not display this prompt in every context; the visible export warning remains authoritative. No browser storage is used. **Forget** clears imported file references, temporary merge choices, previous undo memory, private source and HUMAN history; saved downloads remain the operator's responsibility.

**Important:** snapshots from different original evidence/source SHA values are not merged. This is **offline human coordination only**, not a mechanism to reconcile changed grants, sources or assessment authority. Do not treat the merge as an approval.

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
