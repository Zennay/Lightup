# LightUp Scope Planning Studio (offline, non-authorizing)

## Product

Standalone browser-only workspace at `studio/index.html` with three connected product experiences:

1. **Scope Proposal Studio** (`studio/scope-proposal.html`): prepare and export a client-readable assessment proposal with explicitly proposed asset identities, exclusions, risk 1–4, `AssessmentMode`-compatible value (`analysis_only` or `authorized_assessment`), intended activities, notes/stop instructions, and a local-time planning window. Inline review catches duplicate/invalid literal assets, canonical IPv4/IPv6 aliases, exact and intersecting scope/exclusion CIDRs, and reversed dates; manual review warnings cover CIDR ownership, IPv6, higher risk, and incomplete windows. Display a handoff brief; print or copy it; JSON import/export under 64 KiB, max 80 assets per list. All inputs remain in memory only.
2. **Scope Change Review** (`studio/scope-change-review.html`): load two v1 proposal-draft JSON exports (64 KiB max each), compare exact case-folded asset identities and exclusions, risk, mode, activities, windows, and safety-note changes. Highlight potential expansion separately from restriction and context changes. Shared local `scope-network.js` parses IPv4/IPv6 CIDRs into canonical integer intervals and flags effective new or removed address-space coverage even if differing network notation hides the literal change; DNS remains intentionally unresolved. Export a privacy-minimal, non-authorizing structured review note, excluding free-text purpose content.

3. **Engagement Handoff Builder** (`studio/engagement-handoff.html`): import the client proposal, record client/operator coordination contacts and emergency stop contact, stop conditions, privacy and evidence-handling plan, service/rate limits, rollback and incident procedure. The page surfaces outstanding preparation materials and exports a human-readable dossier and versioned `lightup.engagement_preparation_draft` JSON with literal false consent, authorization, grant, execution and release fields. "Prepared for human review" never equals "authorized".

Open `studio/index.html` from a local checkout in a modern browser; no server, build, dependencies, external scripts, cookies, `localStorage`, database, authentication, fetch/API or real-target contact. Files are downloaded by user action only. For example:

```text
studio/index.html
  ├── scope-proposal.html       → lightup-scope-draft.json
  ├── scope-change-review.html  ← before/after draft files → lightup-scope-change-review.json
  └── engagement-handoff.html   ← draft file → lightup-engagement-preparation.json
      scope-network.js         (shared local address-range analysis)
```

### Format and compatibility

Proposal exports use `kind: "lightup.scope_proposal_draft"`, `schema_version: 1`, `state: "DRAFT_ONLY"`, `requested_assets`, `excluded_assets`, `requested_mode`, `requested_risk`, `notes`, `proposed_activities` and `proposed_window_local`. The review accepts only this v1 shape. Modes correspond to `lightup.engagements.AssessmentMode`; fields are **not** a `DomainStore.create_assessment_request` payload. They contain no authoritative client ID, actor identity, CSRF token, grant, consent signature, or approved request ID.

Review notes use `kind: "lightup.scope_comparison_notes"` and `disposition: "REVIEW_ONLY"` with literal false authentication/consent/authorization/grant/execution/scan/release flags. Local IPv4/IPv6 CIDR interval comparison is a review aid, **not a DNS or execution-policy membership check**. It can detect netblocks containing other netblocks and may warn when semantic address-space differs despite a textual match, but it never proves ownership, exclusion enforcement or that use of a range is allowed. A recorded exclusion does not bind future execution. The studio intentionally does **not** submit the draft to the authenticated portal or write any durable state; a verified client must submit through normal authenticated flows.

### Scope boundaries

- This is **proposal creation and change communication**, not a grant issuer, authorization engine, scope policy, risk approval, active security tool or execution adapter.
- All imported JSON is considered untrusted. The tools never establish the submitter's identity, asset ownership, tenant membership, scope coverage, server-side validity, current revocation, or consent.
- Exports can contain potentially sensitive client notes/assets; review where to share them. This standalone, local-browser experience sends no data over the network.
- Local datetime inputs have no timezone offset. Planning times must be resolved and approved independently in UTC by the operator.
- Risk 4 requires independent risk escalation approval; even `analysis_only` does not grant any operational access.
- Avoid treating a downloaded or printed draft, change-review note or photo as proof of permission. Compare review records only as **human-readable change hints**.

### Integration and release

New paths are isolated within `studio/` and this new document. Operational handoffs contain self-reported coordination data, not authenticated identities or consents. Existing `src/lightup/domain.py`, `src/lightup/webapp/app.py`, all approval/activation/CI/workflows and active parallel PR branches are untouched. Human source-owner integration is required before any authenticated flow consumes a proposal.

**Notion phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Do not merge to default, deploy, issue client grants, scan live assets, dispatch active handlers or claim release completion while the existing gates are unmet: durable approved-request→grant binding (#177), default web source owner (#182), tenant-lineage fix (#829), original hosted CI #301, named permanent VPS CI, real separately authenticated client/operator consent with at-use revocation, independent privacy/security signoff, exact-head review and explicit HUMAN GO.

**No new QA/regression tests or suites** are added by this feature. A source syntax/build inspection is sufficient for this branch's iteration, not a substitute for later mandatory existing CI and security review.
