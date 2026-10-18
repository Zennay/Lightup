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