# LightUp Scope Planning Studio (offline, non-authorizing)

## Product

Standalone browser-only workspace at `studio/index.html` with five connected product experiences:

1. **Scope Proposal Studio** (`studio/scope-proposal.html`): prepare and export a client-readable assessment proposal with explicitly proposed asset identities, exclusions, risk 1–4, `AssessmentMode`-compatible value (`analysis_only` or `authorized_assessment`), intended activities, notes/stop instructions, and a local-time planning window. Inline review catches duplicate/invalid literal assets, canonical IPv4/IPv6 aliases, exact and intersecting scope/exclusion CIDRs, and reversed dates; manual review warnings cover CIDR ownership, IPv6, higher risk, and incomplete windows. Display a handoff brief; print or copy it; JSON import/export under 64 KiB, max 80 assets per list. All inputs remain in memory only.
2. **Scope Change Review** (`studio/scope-change-review.html`): load two v1 proposal-draft JSON exports (64 KiB max each), compare exact case-folded asset identities and exclusions, risk, mode, activities, windows, and safety-note changes. Highlight potential expansion separately from restriction and context changes. Shared local `scope-network.js` parses IPv4/IPv6 CIDRs into canonical integer intervals and flags effective new or removed address-space coverage even if differing network notation hides the literal change; DNS remains intentionally unresolved. Export a privacy-minimal, non-authorizing structured review note, excluding free-text purpose content.

3. **Engagement Handoff Builder** (`studio/engagement-handoff.html`): import the client proposal, record client/operator coordination contacts and emergency stop contact, stop conditions, privacy and evidence-handling plan, service/rate limits, rollback and incident procedure. The page surfaces outstanding preparation materials and exports a human-readable dossier and versioned `lightup.engagement_preparation_draft` JSON with literal false consent, authorization, grant, execution and release fields. "Prepared for human review" never equals "authorized".

4. **Scope Portfolio Board** (`studio/scope-portfolio.html`): import up to 20 separate drafts in the browser, deduplicate by recomputed stable SHA-256 revision, filter by risk/label/asset, summarize declared scopes and analyze potential cross-proposal numeric IPv4/IPv6 overlaps and local planning-window collisions. Download a read-only JSON portfolio and CSV work manifest. No notes or contact details appear in exports, and spreadsheet-formula-leading cells are escaped before CSV download. The board is not the authenticated authorization inbox and does not establish shared tenancy or actual booked windows.

5. **Effective Scope Explorer** (`studio/effective-scope.html`): import an existing untrusted v1 proposal and display the exact numeric IPv4/IPv6 ranges remaining after subtracting the user-declared exclusions. Renders bounded, minimal CIDR fragments, exact integer address counts (as decimal text), literal hostnames and manual-review flags. Export a bounded, explicitly non-authorizing preview; the first 180 CIDR segments are shown and marked truncated when more remain. Does not resolve DNS, prove ownership or enforce execution scope.

Open `studio/index.html` from a local checkout in a modern browser; no server, build, third-party dependencies, remote scripts, cookies, `localStorage`, database, authentication, fetch/API or real-target contact. Files are downloaded by user action only. For example:

```text
studio/index.html
  ├── scope-proposal.html       → lightup-scope-draft.json
  ├── scope-change-review.html  ← before/after draft files → lightup-scope-change-review.json
  ├── engagement-handoff.html   ← draft file → lightup-engagement-preparation.json
  ├── scope-portfolio.html      ← multiple draft files → privacy-minimal portfolio JSON/CSV
  └── effective-scope.html      ← draft file → bounded effective-scope JSON review
      planning-window.js       (browser-local → UTC, DST ambiguity handling)
      scope-network.js         (shared local address-range analysis)
      scope-fingerprint.js     (unsigned stable scope revision SHA-256)
```

### Format and compatibility

Proposal exports use `kind: "lightup.scope_proposal_draft"`, `schema_version: 1`, `state: "DRAFT_ONLY"`, `requested_assets`, `excluded_assets`, `requested_mode`, `requested_risk`, `notes`, `proposed_activities` and `proposed_window_local`. The review accepts only this v1 shape. Modes correspond to `lightup.engagements.AssessmentMode`; fields are **not** a `DomainStore.create_assessment_request` payload. They contain no authoritative client ID, actor identity, CSRF token, grant, consent signature, or approved request ID.

The composer also computes an **unsigned scope revision SHA-256 fingerprint** over stable, canonicalized draft fields (including numerical IPv4/IPv6 identities). Volatile export timestamps are excluded. This identifies versions for collaboration but is **not** a cryptographic signature, authenticated consent, client ownership, or grant. If the browser's local secure context lacks `crypto.subtle`, the composer still works and simply omits the fingerprint. A provided fingerprint in an imported draft must match local recomputation or import is refused. The change-review compares and exports both independently recomputed fingerprints; the engagement handoff repeats the imported proposal fingerprint without turning it into authority. Do not use this as #177 domain request-to-grant evidence.

Review notes use `kind: "lightup.scope_comparison_notes"` and `disposition: "REVIEW_ONLY"` with literal false authentication/consent/authorization/grant/execution/scan/release flags. Local IPv4/IPv6 CIDR interval comparison is a review aid, **not a DNS or execution-policy membership check**. It can detect netblocks containing other netblocks and may warn when semantic address-space differs despite a textual match, but it never proves ownership, exclusion enforcement or that use of a range is allowed. A recorded exclusion does not bind future execution. The studio intentionally does **not** submit the draft to the authenticated portal or write any durable state; a verified client must submit through normal authenticated flows.

### Scope boundaries

- This is **proposal creation and change communication**, not a grant issuer, authorization engine, scope policy, risk approval, active security tool or execution adapter.
- All imported JSON is considered untrusted. The portfolio caps proposal files at 64 KiB each, 20 proposals and 1 MiB input per selection; duplicate revisions are not silently counted as new engagements. The tools never establish the submitter's identity, asset ownership, tenant membership, scope coverage, server-side validity, current revocation, or consent.
- Exports can contain potentially sensitive client notes/assets; review where to share them. This standalone, local-browser experience sends no data over the network.
- Local datetime inputs have no timezone offset. Planning times must be resolved and approved independently in UTC by the operator.
- Risk 4 requires independent risk escalation approval; even `analysis_only` does not grant any operational access.
- Avoid treating a downloaded or printed draft, change-review note or photo as proof of permission. Compare review records only as **human-readable change hints**.

### Integration and release

New paths are isolated within `studio/` and this new document. Operational handoffs contain self-reported coordination data, not authenticated identities or consents. Existing `src/lightup/domain.py`, `src/lightup/webapp/app.py`, all approval/activation/CI/workflows and active parallel PR branches are untouched. Human source-owner integration is required before any authenticated flow consumes a proposal.

**Notion phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Do not merge to default, deploy, issue client grants, scan live assets, dispatch active handlers or claim release completion while the existing gates are unmet: durable approved-request→grant binding (#177), default web source owner (#182), tenant-lineage fix (#829), original hosted CI #301, named permanent VPS CI, real separately authenticated client/operator consent with at-use revocation, independent privacy/security signoff, exact-head review and explicit HUMAN GO.

**No new QA/regression tests or suites** are added by this feature. A source syntax/build inspection is sufficient for this branch's iteration, not a substitute for later mandatory existing CI and security review.

### Recent source refinements: interval semantics and clock provenance

- **CIDR network identity:** a proposed network address must be aligned to its prefix (`192.0.2.0/24` is accepted, `192.0.2.12/24` is refused), so an unaligned host prefix can no longer be silently interpreted as a larger network. This is a proposal syntax fence, **not** an authorization fence.
- **Effective proposed scope:** shared `scope-network.js` subtracts declared numeric IPv4/IPv6 exclusions before producing address-space change or portfolio overlap hints. The Effective Scope Explorer prints a bounded set of minimal CIDR blocks and precise decimal address counts. Textual hostnames are not DNS-resolved and exact-match hostname exclusions are removed locally. Real authorization remains the domain's own separate job.
- **Time provenance:** `planning-window.js` converts local draft windows to UTC using the author's browser timezone and recorded offsets. Spring nonexistent times, ambiguous fall-back times and reversed intervals cannot be exported as resolved windows. Imported source-local wall times and offsets must match the stored UTC instants; cross-timezone editing preserves the original source window until the user explicitly changes the time fields. Missing legacy UTC metadata remains available for human review but cannot establish a clear cross-timezone scheduling comparison.
- **Privacy:** portfolio JSON omits local upload filenames, and all generated review payloads use literal false authorization, consent, grant, execution and release flags. File-import schema checks are bounded and reject malformed or mismatching unsigned scope digests when present.

A self-reported window is still **not** an operator-approved schedule. A SHA-256 checksum is not an authenticated signature and provides no identity assurance. Avoid importing drafts through ordinary network services; the studio does not submit requests, grants or real operations.

