# LightUp Scope Handoff Register — offline human preparation

Open **`scope-handoff-register/standalone.html`** as a single downloaded file, or open **`scope-handoff-register/index.html`** with its sibling `app.js` and `style.css`, directly in a current browser. No installation, account, server, internet connection, remote scripts, API, storage, cookie, database write or live-target connection is required. The multi-file page references only its sibling `app.js` and `style.css`. The portable single file embeds both under SHA-256 pinned inline CSP hashes. Regenerate the same bundle via `python3 scope-handoff-register/build_standalone.py`; it needs only the Python standard library.

**Project phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** The register is *not* an authorization engine, engagement admission, consent workflow, identity or ownership proof, operator grant, release gate or scanner. Its statuses mean only that someone has prepared a human discussion. No test, QA, scan, grant, handler dispatch, deployment or real assessment is performed.

The published standalone build is generated from these exact owned source files; do not edit its inline payload independently. It is a handoff artifact, **not a deployed portal**.

## What a user can do

1. Export one or more draft-only proposals using the existing [Scope Planning Studio v1](https://github.com/Zennay/Lightup/blob/chatgpt/lightup-scope-proposal-studio-20261017/studio/scope-proposal.html). In this register, choose up to 16 JSON files (64 KiB each). Original file bytes are hashed locally (SHA-256) to identify a *revision*, not an identity or signature. Entire selections validate before any mutation; repeats are deduplicated.
2. Work from a searchable risk-priority or outstanding-work queue (with dedicated risk-4 and revision filters) showing proposal risk, intended mode, asset/exclusion counts, source byte fingerprint, literal repeated-asset warnings and preparation progress. The original asset strings and client labels are kept only in page memory and are **not exported**.
3. For each proposal, manage eight human preparation actions: independently proving the contact/ownership route, reviewing assets/exclusions, discussing risk and activities, resolving time windows, agreeing an emergency STOP path, evidence privacy, planning the genuinely authenticated client request, and planning separate operator review. Actions can be open, in discussion, prepared for handoff or requiring revision. Prepared **does not mean authorized**.
4. For coordination meetings, start a selected open action for all currently visible dossiers in one confirmed bulk operation. The bulk command marks **only** `open` items as `working`; it never marks work `prepared`, overrides `needs_revision`, or creates a permission record.
5. Optionally explicitly associate a newer proposal with a previous proposal. The app shows **aggregate literal** differences in assets, exclusions, risk, mode and window presence. This does not establish the same client, infer CIDR coverage, resolve DNS or transfer any approvals. Previous action states **never carry over** to a revision, and cycles or two different successors for the same predecessor are refused.
6. Export a privacy-minimal structured review register JSON, a spreadsheet-safe (fixed-field) actions CSV, a **full script-free printable HTML handoff for every dossier**, or print the current board. Save a separate `lightup.scope_handoff_local_progress` JSON to resume local action states **only after re-importing the exact original source files**. Restore checks exact SHA-256 membership, status sets, false-authority fields and revision graph before any replacement and asks for confirmation.

No free-text asset identities, domain names, requested notes, uploaded filenames, client labels, browser contacts or credentials appear in generated handoff JSON/CSV. The **local progress backup** intentionally includes manually entered short *reference labels* so the user can resume work; choose generic labels without private data and handle that local file privately.

## Unified, read-only human coordination agenda

A complete **combined next-action workboard** now composes four genuinely available offline product flows, without acquiring any of their real permissions: scope dossier preparation, paired overlap discussions, unverified client/operator Permission Brief replies and source-bound human Withdrawal Desk notifications. The new `human-coordination.js` engine ranks all bounded source-linked items (urgent STOP requests first, then independent follow-up, then normal preparation) and yields actionable role-labelled next steps, not another synthetic QA score.

The UI supports type and priority filters, direct navigation to a related dossier, and complete downloadable, privacy-minimal **JSON and CSV**. The full script-free HTML review handoff includes a top-40 prioritized human action summary, with a visible total count and a clear link to the complete machine-readable exports. In addition, locally entered task follow-up **dates** can be exported into an **all-day, tentative, transparent `.ics` calendar** with only task code and original SHA, never client label, assets, risk grant, operator identity or a real scan appointment. The app warns that importing ICS into a calendar service may sync source fingerprints to cloud storage and asks for explicit confirmation. Both exports contain only anonymous dossier indexes, source SHA-256, role, action code, urgency and optional local date. All authority flags are literal `false` and every action remains `REVIEW_ONLY_HOLD`. The workboard never talks to an endpoint, cannot authenticate people or tenants, and does not mark independent consent, STOP confirmation, grant revocation or release as performed. A returned `answered_unverified` reply still creates a real **human follow-up** item requesting independent verification — it is not a completed consent step.



### STOP alerts across self-declared scope revision history

If an imported, unverified Withdrawal Desk STOP/change review refers to one version of a manually linked revision chain, the other versions now show **an explicit historical STOP context warning**. They must be independently confirmed through the genuinely authenticated client/operator workflow; this does not migrate a grant, establish identical ownership, or assert that any real operation was stopped. Potentially stale locally prepared stop/client/operator/scope/risk/planning steps are re-opened as `needs_revision`; related pairwise discussion copies are re-opened. The unified queue surfaces each affected, self-linked version as a separate urgent or high-priority human task without exporting raw asset identities.

## Integrated client/operator Permission Brief replies

The standalone app now imports the **combined human reply reconciliation JSON** from the separately owned [Scope Permission Brief PR #1578](https://github.com/Zennay/Lightup/pull/1578). This is a typed, read-only transfer of **unverified** role-labelled questions: it does not grant identity, legal consent, authenticated operator approval, authorization or execution.

The independent `permission-reply-import.js` parser admits only the existing v1 reconciliation envelope, fixed 12 original literal-`false` authority fields, exact original Studio proposal bytes/SHA-256, matching risk, mode, counts and UTC-state. It checks the role/code allowlist, the question status→next-action contract, duplicate codes, mandatory core questions and open-question counter before committing to an existing dossier. The original Studio-v1 source must already be attached. Import replaces an existing locally attached copy only with confirmation. It never marks an answer 'verified'; it deliberately **reopens prepared local client/operator/ownership/risk/scope preparation steps**, so no older 'prepared' status is mistaken for authenticated consent.

The app displays role-specific and question-specific follow-ups, visually distinguishes missing replies from unverified answers, and includes those privacy-minimal codes and counts in review JSON, text-only HTML and action CSV. Source-bound **local backup v5** retains those annotations alongside original v4 withdrawal records, deadlines, the v2 pair matrix and original action states. Earlier backups remain supported.

## Connected offline Withdrawal Desk review intake

The app can import the **review-only exported JSON packet** produced by the separately owned [Withdrawal Desk PR #1577](https://github.com/Zennay/Lightup/pull/1577) without modifying its branch, routines or files. Import requires the *exact original Studio-v1 proposal bytes* already in this workspace; the full packet must match all source SHA-256 IDs, risks and declared asset/exclusion counts. The separate `withdrawal-import.js` parser requires every nested authority, consent, grant, actual revocation, handler-stop, dispatch, scan, deploy and release field to be **literally false**. It admits only the upstream eight human task code/status pairs and bounded intent/urgency strings; malformed, mixed-source or inconsistent imports fail atomically. A separate local review copy can be removed, but **this never cancels a genuine stop/revocation request**.

Matching dossiers are visually flagged with intent, urgency, proposed UTC time and the number of external actions still without even an unverified request. The product includes a **complete eight-step STOP/withdrawal coordination checklist**, with explanations of which independent client, operator, grant-owner, privacy and incident-registration channels must actually be used. It exports a plain-text, anonymous, source-hash-bound STOP handoff containing the requested intent, urgency, proposed UTC moment and each **unverified** item status; the handoff does not contact any party. Urgent imported requests are prioritised in the local preparation queue, with a dedicated STOP filter.

Any previously prepared local human stop/client/operator/owner action is reopened for review; scope/scheduling/privacy actions are reopened when relevant. A self-reported `stop_all` reopens **all prepared tasks**, rather than leaving an outdated 'prepared' status in place. Existing pairwise discussion notes for those source bytes are cleared. Nothing is sent to the network. The importer **cannot** stop tools, contact customers, revoke grants or authenticate a person; an urgent external flag means only that an untrusted local file declared urgency.

Versioned **v4 local backup** includes the minimal bound external review notes while remaining backward-compatible with v1, v2 and v3 backup files. Structured review JSON, action CSV and printable HTML include only the per-dossier self-reported intent/urgency/outstanding counts — no raw asset identities, personal details or contact notes. This is a **human preparatory handoff**, never at-use revocation enforcement or permission.

## Complete role-based preparation action desk (offline only)

The register now has an **action work queue** over every imported proposal, with separate filters for `client`, `operator`, and `joint` human coordination roles. Each of the existing eight preparation activities has its own optional locally entered ISO `YYYY-MM-DD` **target follow-up date**. Dates do not reserve a UTC assessment window, grant time-limited permission, or represent a regulatory deadline; they simply let a human organise their next conversation.

The queue highlights overdue local dates, tasks due in the next seven days, missing follow-up dates, and scope revision items that need re-discussion. Open each action's actual dossier directly from the queue. The queue displays up to 64 actions at a time for mobile readability; use filters to view the rest. The complete, anonymised action list remains available via CSV, JSON and script-free HTML.

Local backup schema version **3** retains these task follow-up dates and all earlier v2 pairwise meeting statuses, after source SHA matching and complete per-action date/type and authority checks. Existing v1/v2 backups remain readable (older backups have no saved due dates, which restore as unset). Exports include **roles, ISO dates, source byte identifiers and human preparation states only**; no names of people, client identities, raw IPs, hostnames, security notes, credentials or signatures.

### Revision-to-reassessment flow

When a human explicitly links a new Studio revision to an older source, the app now distinguishes that revision chain from unrelated proposals in the overlap agenda. It reopens locally prepared actions affected by a changing scope/risk/mode/time window, marks the affected rows `needs_revision`, and clears discussion statuses for affected pair relationships. A recorded meeting is never retained as an approval of a different scope. A local revision link does not assert common authenticated ownership or grant re-use.

## Integrated Studio v1 provenance and cross-proposal coordination

This standalone product includes **unchanged source snapshots** of the already existing Studio v1 parser and fingerprint and UTC conversion modules (source on [Scope Planning Studio PR #1567](https://github.com/Zennay/Lightup/pull/1567)):

- `studio-network-v1.js` — original `studio/scope-network.js` blob `f82c148488b1066e6f49b4110fab12fa48982e4d`
- `studio-fingerprint-v1.js` — original `studio/scope-fingerprint.js` blob `44238a1ef62e730a1307b42a8505c49067e5ca10`
- `studio-window-v1.js` — original `studio/planning-window.js` blob `1eeeb0a582080b8a387db7854b794fe55d7c04d1`

The source-owner Studio files were **not changed**. Their original functions now validate imported canonical host/IP/CIDR syntax, any stored Studio semantic SHA-256 fingerprint, and source-local-wall/UTC-offset consistency before a proposal is admitted to the handoff board. Both the immutable original **file-byte** SHA-256 and the Studio's stable, unsigned **semantic** scope revision SHA-256 are shown in the human export as separate non-authorizing identifiers. No trust in user-provided SHA fields, consent, network access, client identity, real schedule or release is inferred.

The cross-proposal agenda is a functional **human follow-up workboard**: each computed scope/UTC-conflict pair can be marked locally `open`, `discussion_started`, `needs_followup` or `discussion_recorded`. Even the last status means only a human reported a conversation, not that the conflict is cleared. The local progress backup format is now **v2** with an exact source-pair list and each pair's status; previous v1 backups remain readable and start agenda entries as open. Restore checks the entire exact-byte input set, full pair topology, duplicate/cyclic revision links, literal false authority flags and all statuses *before* asking whether to replace any current work. Deleting a source discards related pair notes. The complete script-free HTML handoff, review-only JSON and dedicated fixed-field agenda CSV include only anonymous dossier indexes, overlap flags and self-reported follow-up statuses.

The revised board uses local `effectiveCoverage` and `coverageDifference` to reason about IPv4 and IPv6 numeric intervals **after explicit exclusions** and literal exact-hostname equality. A new pairwise review agenda exposes which two dossiers share possible effective numeric/literal scope, proposed UTC window, or both. It links back to each proposal's local human action work. The script-free full HTML packet and review-only JSON contain only generic counts/flags and dossier indexes — never the original IP/hostname strings or imported personal notes. Numeric interval overlap is not proof that two projects have a common owner or tenant; literal hostnames are not resolved through DNS and recorded windows are not reservations.

**Integration limitations:** a Studio draft export may also include volatile `exported_at_utc`; the exact-byte SHA records that input separately from the deterministic semantic Studio revision. No source byte or semantic SHA is a signature, provenance credential, or permission. Imported UTF-8 is decoded **fatally** rather than silently substituting corrupted bytes; raw file-byte SHA-256 is computed before decoding. Byte-identical imports and semantically identical Studio revisions with only export timestamps or JSON formatting changed are not duplicated as new cases. For a local backup to restore, the same **original file bytes** must be reopened (semantic equivalence alone is intentionally insufficient). If Studio v1 modules change in their separately owned PR, human review must reconcile the vendored source before integration.

## Actual Studio v1 contract

Required: `kind: "lightup.scope_proposal_draft"`, `schema_version: 1`, `state: "DRAFT_ONLY"`, `requested_assets` and `excluded_assets` (arrays of strings), `requested_mode` (`analysis_only` or `authorized_assessment`), `requested_risk` (integer 1–4), the **object** `proposed_activities` with three boolean flags (`passive_analysis`, `configuration_review`, `private_lab_network_checks`), and `proposed_window_local`. The six original safety fields `authorization`, `client_consent`, `operator_consent`, `grant`, `execution`, `revocation_checked` must all be literally `false`. A resolved UTC planning proposal is a scheduling hint only.

Import rejects duplicate decoded JSON object keys, malformed v1 envelope types, oversized or deeply nested files and unauthorized elevated safety fields. The app never fetches external URLs or sends data.

Every exported review and progress envelope is `REVIEW_ONLY_HOLD` with nine literal denial flags for authenticated identity, consent, authorization, grants, execution, scanning, dispatch, deployment and release. This is **informational evidence of self-reported preparation only**. A SHA-256 fingerprint cannot prove who prepared a file.

## Integration boundary

This additive, isolated standalone tool deliberately changes no files in the source-owned `src/lightup/domain.py`, `src/lightup/webapp/app.py`, activation/execution gates, client/operator PRs, original Studio sources, workflow gates or permanent runner. A source owner must decide whether and how to link handoffs to the **actual separately authenticated, at-use-revocable** client and operator process.

Before *any* promotion, LightUp still requires #177 approved-request→grant provenance, #182 input protection, #829 tenant-safe durable grant reads, original hosted and permanent named-VPS CI on the approved exact head, independent security/privacy review and an explicit HUMAN GO. This draft must **not** be merged, deployed or treated as actual client consent while these requirements are unmet.

### Quick operation

- In Studio, export `lightup-scope-draft.json`.
- Here, choose its JSON. Use the action selector for each of the eight items.
- To review a revised scope, import the *new* file and use “Voorganger koppelen”; do **not** copy task statuses.
- Use “Bewaar lokale voortgang” for local resume. Re-open the same original drafts, then “Herstel voortgang”.
- Use “Exporteer review-JSON” or CSV for non-authoritative human coordination.

No new QA, regression or test suite belongs to this work. A direct JS syntax inspection may confirm source validity, but does not replace the project's existing required gates.
