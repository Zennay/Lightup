# LightUp Scope Handoff Register — offline human preparation

Open **`scope-handoff-register/standalone.html`** as a single downloaded file, or open **`scope-handoff-register/index.html`** with its sibling `app.js` and `style.css`, directly in a current browser. No installation, account, server, internet connection, remote scripts, API, storage, cookie, database write or live-target connection is required. The multi-file page references only its sibling `app.js` and `style.css`. The portable single file embeds both under SHA-256 pinned inline CSP hashes. Regenerate the same bundle via `python3 scope-handoff-register/build_standalone.py`; it needs only the Python standard library.

**Project phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** The register is *not* an authorization engine, engagement admission, consent workflow, identity or ownership proof, operator grant, release gate or scanner. Its statuses mean only that someone has prepared a human discussion. No test, QA, scan, grant, handler dispatch, deployment or real assessment is performed.

The published standalone build is generated from these exact owned source files; do not edit its inline payload independently. It is a handoff artifact, **not a deployed portal**.

## What a user can do

1. Export one or more draft-only proposals using the existing [Scope Planning Studio v1](https://github.com/Zennay/Lightup/blob/chatgpt/lightup-scope-proposal-studio-20261017/studio/scope-proposal.html). In this register, choose up to 16 JSON files (64 KiB each). Original file bytes are hashed locally (SHA-256) to identify a *revision*, not an identity or signature. Entire selections validate before any mutation; repeats are deduplicated.
2. Work from a search/filterable board showing proposal risk, intended mode, asset/exclusion counts, source byte fingerprint, literal repeated-asset warnings and preparation progress. The original asset strings and client labels are kept only in page memory and are **not exported**.
3. For each proposal, manage eight human preparation actions: independently proving the contact/ownership route, reviewing assets/exclusions, discussing risk and activities, resolving time windows, agreeing an emergency STOP path, evidence privacy, planning the genuinely authenticated client request, and planning separate operator review. Actions can be open, in discussion, prepared for handoff or requiring revision. Prepared **does not mean authorized**.
4. Optionally explicitly associate a newer proposal with a previous proposal. The app shows **aggregate literal** differences in assets, exclusions, risk, mode and window presence. This does not establish the same client, infer CIDR coverage, resolve DNS or transfer any approvals. Previous action states **never carry over** to a revision, and cycles or two different successors for the same predecessor are refused.
5. Export a privacy-minimal structured review register JSON, a spreadsheet-safe (fixed-field) actions CSV, or print the board. Save a separate `lightup.scope_handoff_local_progress` JSON to resume local action states **only after re-importing the exact original source files**. Restore checks exact SHA-256 membership, status sets, false-authority fields and revision graph before any replacement and asks for confirmation.

No free-text asset identities, domain names, requested notes, uploaded filenames, client labels, browser contacts or credentials appear in generated handoff JSON/CSV. The **local progress backup** intentionally includes manually entered short *reference labels* so the user can resume work; choose generic labels without private data and handle that local file privately.

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
