# Scope Permission Brief · client/operator comprehension handoff

## Product behavior

Open the fully self-contained [`scope-permission-brief/standalone.html`](https://github.com/Zennay/Lightup/blob/chatgpt/lightup-scope-permission-brief-20261018/scope-permission-brief/standalone.html) after saving it locally; no other asset, package, install or service is needed. The multi-file development source remains at `scope-permission-brief/index.html`. The offline build `python3 scope-permission-brief/build_standalone.py` embeds exactly the project JS/CSS and pins their bytes using SHA-256 CSP hashes. This is packaging, not a QA gate.

This is a **privacy-minimal audience-specific comprehension explainer** for original `lightup.scope_proposal_draft` v1 exports produced by the existing Scope Planning Studio. It is intentionally separate from the Studio's technical scope diff, the source-bound coordination tracker, encrypted Vault, authenticated request desk, and withdrawal tool.

A client sees the **meaning and limits of a proposed assessment**, with tailored plain-language clarification questions; an operator sees independent-review responsibilities and STOP/revocation, tenant/scope and risk reminders. Import displays only aggregate declared asset and exclusion counts, requested mode and risk, and tentative window status. Proposed target names/IP addresses, client label, free-text notes and source bytes **never appear in app-generated previews or exported briefs**. The browser's native local file chooser may show the selected filename, so use an appropriate private device. Case-specific safety notes stay solely in volatile, original local source data.

The viewer derives an action queue with explicit human-only status: unanswered, question sent, answered/unverified. Dynamic questions cover elevated risk 4, lab-network interaction, missing exclusions, unresolved UTC windows, and missing purpose/stop notes. None of those states means approved. Client/operator audience can be changed without rewriting the source; printed and JSON views are bounded, generic and privacy-minimal.

Operators can also **import a previously downloaded review brief back against the original exact source bytes**. Strict import rejects wrong SHA-256, conflicting count/mode/risk, any changed false security flag, altered question order/role, duplicate JSON keys and inconsistent unresolved counts **before** restoring any statuses. Restored statuses remain human self-reports, not approval. A second button creates a plain-language, role-specific `.txt` handoff with only anonymous question headings and generic counts; it cannot contain the original source labels or target values.

The downloaded JSON file contains `kind: lightup.scope_permission_brief`, `schema_version: 1`, `state: REVIEW_ONLY_HOLD`, SHA-256 over **exact local input bytes**, counts, requested risk/mode, anonymous question codes/states and twelve literal false authority/release flags. SHA-256 is an unsigned correlation hint: it cannot identify the signer, client, owner or origin and cannot grant consent. The viewer and return desk never contact endpoints, processes tokens/credentials, edits the Studio source, records identity, captures signatures or creates a grant.

## Two-role return reconciliation and human meeting pack

The same offline application now includes a **client/operator return desk**. Start with the original Studio-v1 proposal, then import up to one self-labelled client preparation note and one separately self-labelled operator preparation note. Both must be previously exported `lightup.scope_permission_brief` REVIEW_ONLY_HOLD JSON for the **same exact original source bytes**. Role labels are **not verified identities**, and the tool is incapable of accepting or granting consent.

Each incoming return is capped at 64 KiB with fatal UTF-8 decoding, duplicate-key refusal and exact schema validation. A return must preserve all original counts, mode, risk, window, source SHA-256, literal false flags and question-code/order/role identities. A client-labelled packet may change *only* client-assigned question statuses; an operator-labelled packet may change *only* operator-assigned statuses. Other-role statuses must stay `unanswered`, preventing an accidentally or intentionally cross-labelled packet from being reported as an independent role response. This remains a **self-declared** role distinction, not authentication.

The primary brief export itself now enforces the same role boundary: selecting the client audience serializes only client-owned question statuses (all operator entries are `unanswered`), and vice versa. Importing a return restores only that audience's statuses and preserves local work for the other role. This fixes cross-role reply impersonation and accidental overwrites without claiming real independent authentication.

The return desk leaves its existing accepted notes untouched if an incoming return fails. Replacing a materially different already loaded note requires an explicit local confirmation; clear/original-source changes forget both packets. Missing replies remain visible. Consolidation produces a fixed `lightup.scope_permission_reply_reconciliation` JSON with disposition `REVIEW_ONLY_HOLD`, missing/unanswered/question-sent/unverified-response states, generic next-action codes, the original SHA-256 and the same literal false authority/grant/release fields. A spreadsheet-safe CSV lists code, role, status and next action without source labels or free-text data.

A **script-free, read-only HTML meeting pack** is also downloadable for an offline human review. It groups pending and unverified questions by self-labelled role, sorts missing replies first, prints cleanly and includes an explicit HOLD banner. It embeds no scripts, network resources, target identities, contact names, raw notes or credentials. Exported printable material is not client consent or an operator decision.

All three return-desk exports (JSON, CSV, read-only HTML) are optional downloads from the local browser only. The existing user-selected roles and question state edits remain strictly non-authorizing. The native browser's file picker can display a filename even though app-generated previews/exports do not.

## Resume an offline human return desk without storing consent

A returned `lightup.scope_permission_reply_reconciliation` JSON may now be loaded into a **new browser tab/session after re-importing the original Studio-v1 source**. The app never persists the original source, role notes or return desk into storage. Restore is strictly local, optional, and read-only with respect to production endpoints.

The 64-KiB combined note undergoes duplicate-key refusal and exact source-SHA, original mode/risk/count/window and literal FALSE authority-field verification. Every question must appear in the exact original order with the same fixed role, permitted self-reported status and matching next-action code; aggregated attention and role-presence fields must agree. The whole packet is preflighted **before** any previously loaded human preparation is replaced. A materially different existing role return requires explicit confirmation. On failure the previous work remains intact and the whole import gets HOLD.

Successful restore reconstructs only anonymous, **self-labelled and unverified** client/operator question statuses, restoring the useful human coordination board and its JSON/CSV/HTML exports. It never reconstructs raw target/client details, proof of identity, authenticated client/operator consent, a request approval, grant, permission or revocation decision. Exact original source file access is needed to resume; a returned combined JSON alone is intentionally insufficient.

## Revision-safe source replacement and reply reissue

**A completed human preparation note never follows a changed scope automatically.** With a first Studio v1 draft loaded, select a later draft in the same file chooser. The viewer verifies the full new file **before changing any existing local data**. If it is invalid, oversized or contradictory, the earlier accepted draft and its human replies remain intact with an explicit HOLD message. Re-importing **identical exact source bytes** retains existing human answers and returns. An accepted different byte stream switches the current draft atomically, clears the previous source-bound preparation/returns, and adds a privacy-minimal record to the local revision board.

The revision board tracks up to **12** local old/new SHA-256 byte fingerprints and category-only changes in requested mode, risk, asset count, exclusion count and UTC-status. Identical counts do not prove identical targets, notes, consent or scope: this board does **not** perform a semantic asset comparison. It explicitly marks every old human reply stale, and instructs both roles to prepare a new review. A session-only timeline can be exported as REVIEW_ONLY_HOLD JSON or spreadsheet-formula-safe CSV. There are no names, IP addresses, source body, comments, file paths, timestamps claimed as trusted evidence, signatures or permission claims.

Buttons prepare **fresh client- and operator-specific JSON response templates** for the currently loaded source (every question unanswered; opposite-role entries also unanswered). These packets intentionally conform to the same strict input envelope used by the existing human return desk, so a recipient can separately review the *matching original Studio source* locally and then return a role-specific preparation note. They do **not** carry earlier answers, transfer actual consent or prove a party's identity. If an actor lacks the original scope proposal, this anonymous template cannot authenticate or reconstruct it.

The **Forget draft & answers** action clears current source, replies, and the entire volatile revision timeline. The optional timeline-only clear leaves the current source unchanged. Temporary parsing failures do not create false revision events or erase accepted drafts. This is a usable human coordination feature, never an executable policy / authorization amendment.

## Human-readable scope change impact (literal, not an authorization verdict)

When replacing one accepted Studio proposal with another inside the same browser tab, LightUp now analyzes **literal, case-insensitive** membership of the two `requested_assets` and `excluded_assets` string arrays. It reports **aggregate counts only** of added, removed and retained entries for both lists; original hostnames/IPs, excluded strings, and per-asset fingerprints never cross the event into review history or exported files. In addition, the review tracks private safety-note change as a boolean, selected activity-code changes, title/client-label changes as booleans, and tentative UTC/local window differences. It does **not** normalize network CIDRs, resolve DNS, check effective policy membership, verify ownership, or produce an authorization verdict: different textual entries may denote equal numeric ranges or aliases.

Changes that merit extra **human attention** receive fixed category prompts: added literal included entries, removed literal exclusions, raised risk, requested assessment mode escalation, newly proposed private-lab network activity, modified window/STOP time, scope restriction changes, and modified private safety notes. These are **review priorities, not authenticated execution decisions**. On a changed source, the role-specific original brief gains two extra human-only questions to re-confirm source ownership and independently reassess enforceable authorization boundaries.

The revision tab displays literal aggregate changes and fixed review advice, extends the anonymous revision JSON and spreadsheet-safe CSV with these categories, and can export a **script-free, printable HTML impact pack** for the latest change. The handoff contains only original/new document-level SHA-256 fingerprints, summary counts, fixed category descriptors and fresh human-review instructions. It carries **no raw assets, contacts, notes, secrets, per-item hashes, permission grants, consent proofs or action authorizations**. Equal counts and absent elevated codes never remove HOLD.

## Strict import and privacy boundaries

- Maximum one 64-KiB original UTF-8 file; invalid bytes, unsupported schema, empty asset list, malformed activities, duplicate JSON keys **at any depth**, unsafe prototype-style keys, unknown authority fields, ambiguous source boolean flags and unsafe control text are refused. Multi-line safety notes are accepted (line breaks and tabs only) but never rendered or re-exported.
- Only `kind=lightup.scope_proposal_draft`, `schema_version=1`, `state=DRAFT_ONLY`, **literal false** authorization/client_consent/operator_consent/grant/execution and revocation_checked (if supplied) are accepted. This is source acceptance, not trust.
- Resolved UTC planning windows must match the original signed offsets and valid local dates; unknown/malformed statuses fail closed. A resolved planning window remains **unapproved**.
- Imported `scope_fingerprint_sha256` is syntax checked but **not independently authenticated or recomputed by this explainer**. The viewer's output references only a fresh digest of the exact imported bytes.
- HTML uses a restrictive meta CSP forbidding external resources and connections. JavaScript uses file input and local WebCrypto SHA-256, DOM text nodes (not raw markup), local Blob download and Print only. There is no localStorage, cookies, analytics, remote JS, fetch, database or background activity. Clear immediately forgets the in-memory source and human answers; browser-managed original file permissions remain outside this app's control.
- Operator/client statuses are **entirely self-reported logistics**, not authenticated evidence or actual consent. `answered_unverified` does not remove HOLD.

## Integration

Source is isolated to four **new** paths:

- `scope-permission-brief/index.html`
- `scope-permission-brief/style.css`
- `scope-permission-brief/app.js`
- `scope-permission-brief/reconciliation.js` (separated, read-only reply coordination)
- `scope-permission-brief/revision.js` (source-byte revision timeline and fresh human reissue)
- `scope-permission-brief/build_standalone.py`
- `scope-permission-brief/standalone.html` (generated, one-file offline edition)
- `docs/scope-permission-brief.md`

Existing Scope Studio PR #1567, coordination #1573, Vault #1574, withdrawals #1577, authenticated request/decision/grant source-owner PRs #1566/#1570/#1571 and mandatory CI/workflows stay untouched. This is an independently reviewable additional browser product, **not** a replacement or implementation of any of those PRs, nor an authenticated authorization gate.

## Release posture

LightUp remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. The feature must not be presented as a permission issuer, approval, asset-ownership verifier, scope-membership decision, risk approval, grant, release proof or live adapter. No real target, scan, handler, request/grant or deployment is triggered. Source owner integration, exact-head canonical hosted CI and permanently registered named-VPS CI, independent security/privacy review, genuine separately authenticated client and operator consent, at-use revocation, and explicit human GO remain required before any production merge, activation or deploy.

The user-directed 2026-10-17 execution policy forbids adding or running new QA/regression/testing suites; only ordinary source syntax/build inspection is permitted. No new QA scripts or gates have been added.
