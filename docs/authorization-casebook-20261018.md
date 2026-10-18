# LightUp — authenticated Authorization Casebook

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** New independent, credential-backed and tenant-isolated source review; no execution/grant/consent/scan.

## Original authenticated workflow

The casebook uses the original persisted DomainStore credentials and brute-force lockout. Login occurs before a query-only SQLite snapshot, with current stored role and tenant rechecked inside the same read snapshot. A client can only read its own tenant. An operator must explicitly pick one tenant.

Discover selected real tenant IDs (operator) or your own tenant ID (client):

    PYTHONPATH=src python -m lightup.auth_casebook \
      --database /private/lightup.sqlite \
      --email original-operator@example.invalid --list-clients

Create ONE original-source private casebook file:

    umask 077
    PYTHONPATH=src python -m lightup.auth_casebook \
      --database /private/lightup.sqlite \
      --email original-operator@example.invalid \
      --client ORIGINAL_TENANT_ID \
      --output /private/NEW-original-casebook.json

Client accounts may omit --client but cannot select another tenant. The original login mechanism can write to original lockout/login counters; casebook source queries never change requests, grants, risk approvals, engagements or permissions.

Password is collected through a private interactive prompt, NEVER a CLI argument. A private output contains opaque client, request, engagement and grant identifiers; store only in a trusted, private local directory. It is exclusively created 0600 using temporary same-directory fsync + atomic no-replace link publication. If any source/authentication/output precondition fails, the result is HOLD and no new final output is published.

## Useful product behavior

- View recorded request status, mode, risk and decision-presence; these are untrusted retrospective records, never newly created approvals.
- See original engagements, stored grants, source-declared request IDs and associated risk rows without a scan/model/handler. Foreign-tenant rows are never imported wholesale; only anonymous counts tied to the selected tenant's own engagement IDs are reported, and malformed cross-tenant engagement identities are withheld.
- Identify stored grants lacking an approved request link, referencing a missing/not-approved request, or contradicting stored tenant/engagement provenance. HOLD means human follow-up, not an authorization gate bypass.
- Per-engagement caseboard combines counts of stored grants and risk decisions, source status and a descriptive attention label. A matching source link is explicitly REVIEW_ONLY_UNVERIFIED_GRANT_LINK, never a verified grant.
- Operator can select one existing tenant by authenticated client-ID list; client login is hard-bound to the actual persisted tenant.

CLI returns exit 2 for REVIEW_ONLY and 3 for HOLD, never success as an authorization decision. ALL outputs explicitly have source_authenticated, client_consent_verified, operator_consent_verified, authorization_granted, execution_allowed and release_approved equal to false. Its source file is unsigned, even if generated after a real local account login. Client names, addresses, notes, detailed asset lists, passwords and evidence are not printed.

## Graphical offline casebook

Open authorization-casebook/standalone.html from a local checkout. The responsive single-file HTML/CSS/JS browser app accepts ONE original private casebook JSON. Bounded 512 KiB import rejects duplicate JSON keys, schema/authority contradictions, duplicate record identities and mismatching caseboard/HOLD counts. Invalid imports preserve the previous tab state.

Filter original requests, engagements, stored grant links, risk decisions and the combined engagement caseboard. The source-timestamp timeline is declared order only, not authenticated chronology. Local print and aggregate-only JSON exclude private original identities, addresses, references, users and raw source. The fictional demo is labeled. No network requests, browser storage, browser credential input, grants, target activity, scanners, dispatch or external scripts.

## Isolation and mandatory release gates

Three entirely NEW owned paths only. The branch is stacked on immutable held candidate scope/lab PR #1618; it does not edit current #1570 domain owner, active emergency STOP PR #1619, production app, policy, scanner, existing workflows or QA suites. No manually started QA tests or regression suites.

Status DRAFT/HOLD. The product does not apply the original authoritative approved_request_is_compatible, actual asset/capability/policy, separate client/operator authenticated consent, at-use revocation, risk/activation, or release checks. This is not deployable production authorization. Original hosted + permanent registered VPS exact-head CI, independent owners and security/privacy review, real consent and HUMAN GO remain mandatory. Do NOT merge to main or deploy until all original conditions are met.
## Engagement inspection, human follow-up, and snapshot comparison

The offline caseboard now has Inspect case actions. The selected original engagement displays source-linked stored grants, the corresponding existing request's recorded state, and associated risk decisions, without manufacturing an approval. A client-visible foreign engagement identity is never required to inspect its own case. All rendering uses ordinary text nodes rather than injecting imported source HTML.

For each selected engagement the reviewer may set a TEMPORARY local human follow-up stage: unreviewed, investigating, escalated, or documented. It lives only in this browser tab, has no effect on original SQLite state or any authorization decision, and is reset on new source import or clear. The aggregate JSON exports counts by local human stage only — not original IDs or private notes.

An optional separate earlier original PRIVATE Casebook JSON can be loaded into the same local browser after the current snapshot, and must declare the exact same tenant. The comparison counts newly recorded rows, absent rows and status changes across the four original source record types: requests, engagements, grants and risk approvals. Derived caseboard rows are not double-counted. Snapshot order and timestamps remain UNSIGNED, source-declared and untrusted: this is human follow-up, never audit-trusted chronology, revocation or runtime permission. The earlier source is kept only in memory and is excluded from aggregate handoff except for anonymous counts.

The browser intentionally cannot upload, persist, share or remotely authenticate a source: private input must be handled only on a trusted workstation, and exported aggregates are REVIEW_ONLY.
## Original request-to-grant evidence, recorded windows, terminal work queue

The source reader reuses ORIGINAL `grant_request_binding.approved_request_is_compatible` against a persisted joined request row and the stored grant's private `assets_json` (not exported), created_at and max_risk. The source check covers the requester's persisted client role, the independent reviewer operator role, matching tenant, prior UTC decision, approved assessment mode, bounded risk, and exact conservative approved asset coverage. A mismatch is `HOLD_REQUEST_SCOPE_OR_PROVENANCE_MISMATCH`, while a matching source becomes `REQUEST_SCOPE_COMPATIBLE_UNVERIFIED` — never a grant confirmation, actual consent or target permission.

Every stored grant additionally carries `validity_observation`: `EXPIRED_RECORDED_WINDOW`, `FUTURE_RECORDED_WINDOW`, `HOLD_INVALID_RECORDED_WINDOW`, or `WITHIN_RECORDED_WINDOW_NOT_AUTHORITY`. These are retrospective source observations at the ONE local snapshot timestamp; the original execution authority still requires at-use current time, live grant resolution, true client/operator consent and all original gates.

The caseboard adds a concrete next_review_action for every engagement, prioritizing source tenant/provenance failures, closed engagements carrying grants, expired/future original windows, then missing grants versus source links that still need genuine independent consent. Its labels are human workflow suggestions only, never preconfigured scanner/runtime actions.

To view a single tenant's actual review queue directly in your terminal (without private JSON output):

    PYTHONPATH=src python -m lightup.auth_casebook \
      --database /private/lightup.sqlite \
      --email operator@example.invalid --client ORIGINAL_TENANT_ID --cases

`--cases` is separate from `--list-clients`. Both require original password authentication. The terminal caseboard includes only owned engagement IDs, original source status, bounded count and next-action labels, not personal contact details, raw assets, grant references, passwords, scans or evidence. CLI exit remains 2 REVIEW_ONLY, 3 HOLD.

## Source follow-up queue and portable privacy-safe handoff

The offline browser now shows a distinct prioritized operator follow-up queue with one-click Inspect original case and the local in-tab human review stage. A human can export an additional SELF-CONTAINED, SCRIPTLESS anonymous HTML briefing, with original source count totals, HOLD categories, locally assigned review stages and two-source comparison counts. It contains zero original request/engagement/grant IDs, client metadata, hostnames, evidence, contacts or notes. Local file export, no network.

No new test, regression or quality-validation suite was written or run. Existing hosted and named VPS CI remain original release dependencies; the code was inspected only by Python compilation, native command help and HTML JavaScript syntax.