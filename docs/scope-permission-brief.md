# Scope Permission Brief · client/operator comprehension handoff

## Product behavior

Open `scope-permission-brief/index.html` from a local checkout (or after downloading the complete directory, keeping HTML, JS and CSS together). No package install or service is needed.

This is a **privacy-minimal audience-specific comprehension explainer** for original `lightup.scope_proposal_draft` v1 exports produced by the existing Scope Planning Studio. It is intentionally separate from the Studio's technical scope diff, the source-bound coordination tracker, encrypted Vault, authenticated request desk, and withdrawal tool.

A client sees the **meaning and limits of a proposed assessment**, with tailored plain-language clarification questions; an operator sees independent-review responsibilities and STOP/revocation, tenant/scope and risk reminders. Import displays only aggregate declared asset and exclusion counts, requested mode and risk, and tentative window status. Proposed target names/IP addresses, client label, free-text notes, filenames and source bytes **never appear in the UI or exported brief**. Case-specific safety notes stay solely in volatile, original local source data.

The viewer derives an action queue with explicit human-only status: unanswered, question sent, answered/unverified. Dynamic questions cover elevated risk 4, lab-network interaction, missing exclusions, unresolved UTC windows, and missing purpose/stop notes. None of those states means approved. Client/operator audience can be changed without rewriting the source; printed and JSON views are bounded, generic and privacy-minimal.

The downloaded file contains `kind: lightup.scope_permission_brief`, `schema_version: 1`, `state: REVIEW_ONLY_HOLD`, SHA-256 over **exact local input bytes**, counts, requested risk/mode, anonymous question codes/states and twelve literal false authority/release flags. SHA-256 is an unsigned correlation hint: it cannot identify the signer, client, owner or origin and cannot grant consent. The viewer never contacts endpoints, processes tokens/credentials, edits the Studio source, records identity, captures signatures or creates a grant.

## Strict import and privacy boundaries

- Maximum one 64-KiB original UTF-8 file; invalid bytes, unsupported schema, empty asset list, malformed activities, duplicate JSON keys **at any depth**, unsafe prototype-style keys, unknown authority fields, ambiguous source boolean flags and unsafe control text are refused.
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
- `docs/scope-permission-brief.md`

Existing Scope Studio PR #1567, coordination #1573, Vault #1574, withdrawals #1577, authenticated request/decision/grant source-owner PRs #1566/#1570/#1571 and mandatory CI/workflows stay untouched. This is an independently reviewable additional browser product, **not** a replacement or implementation of any of those PRs, nor an authenticated authorization gate.

## Release posture

LightUp remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. The feature must not be presented as a permission issuer, approval, asset-ownership verifier, scope-membership decision, risk approval, grant, release proof or live adapter. No real target, scan, handler, request/grant or deployment is triggered. Source owner integration, exact-head canonical hosted CI and permanently registered named-VPS CI, independent security/privacy review, genuine separately authenticated client and operator consent, at-use revocation, and explicit human GO remain required before any production merge, activation or deploy.

The user-directed 2026-10-17 execution policy forbids adding or running new QA/regression/testing suites; only ordinary source syntax/build inspection is permitted. No new QA scripts or gates have been added.
