# Operator read-only client portal — opt-in web integration

**Issue:** [#673](https://github.com/Zennay/Lightup/issues/673). **Posture:** INCUBATE M3/M7, PLAN/LAB ONLY. This is a client-request provenance safeguard, not permission to scan targets, issue grants, deploy, or ship a production release.

## Product behavior

The existing operator account can open `GET /portal/<client_id>` to inspect a client's findings and assessment requests. The existing normal web shell also lets that operator submit `POST /portal/<client_id>/requests` through a synthetic `CLIENT_ADMIN` view context. That permits an operator-originated request to appear as though it came from the client.

`OperatorReadOnlyWebApp` introduces an opt-in WSGI integration that separates these roles:

- An operator can **read** any client portal but sees a "Client action only" status instead of the assessment request form.
- Every **operator POST** to any `/portal/` path returns HTTP **403**, before the underlying route handler can submit or change a request. This also protects future portal POST routes.
- The assessment request handler requires a real, session-derived `AccessContext` with `CLIENT_ADMIN` or `CLIENT_MEMBER` and an *exactly matching client ID*. It does not use the operator-to-client display-context conversion for mutations.
- Authenticated, same-tenant clients retain the normal request form and request-submission path, including existing CSRF protection and domain-level tenant isolation.
- Operator-owned `/assessments/...` review and approval routes are unchanged. No database schema, grant lifecycle, real-target capability, network scanner or execution authority is changed.

## Local use (explicit opt in)

From a checkout with LightUp installed on the Python import path:

```sh
PYTHONPATH=src python -m lightup.webapp.operator_readonly --db lightup.db --host 127.0.0.1 --port 8767
```

The development launcher **only accepts loopback IP addresses**. It does not attempt to deploy anything.

Embedding in existing WSGI applications:

```python
from lightup.domain import DomainStore
from lightup.webapp.operator_readonly import create_readonly_app

application = create_readonly_app(DomainStore("lightup.db"))
```

For an **explicitly configured** production WSGI application (not a deployment instruction):

```python
from lightup.webapp.operator_readonly import create_production_readonly_app

application = create_production_readonly_app()
```

The production factory delegates to LightUp's existing mandatory HTTPS public-origin, absolute database path and trusted-loopback-proxy validation. It requires `LIGHTUP_PUBLIC_ORIGIN` and `LIGHTUP_DB` and optionally accepts `LIGHTUP_TRUSTED_PROXY_IP`. It does not create users or grant authorization.

## Boundaries and integration

This intentionally **does not alter** `src/lightup/webapp/app.py`, which is still owned by [PR #182](https://github.com/Zennay/Lightup/pull/182), or `src/lightup/domain.py` / consent sources owned by other workers. The original unguarded `create_app` and its default development/production entrypoints are unchanged. To gain this behavior, consumers must **explicitly switch** to the guarded factory or launcher. The default application remains affected until the web source owner integrates an equivalent guard after collision-free review.

This branch is an implementation candidate, **not** a release/consent certificate. Do not merge or deploy under the current HOLD posture without the existing independently authenticated client/operator consent and revocation requirements, security/privacy review, exact approved release-head hosted and registered VPS CI, and explicit human GO. No new QA or regression suite is included in this deliverable.

## Operator authorization desk (read-only product screen)

The same guarded app also adds:

- `GET /authorization-desk` — an operator-only overview of clients, pending assessment requests, current requester-account provenance observations, engagement records and *time-current grant records*.
- `GET /authorization-desk/clients/<client_id>` — a specific client's requests and engagements without synthesizing a client session. The domain layer resolves the named client through the operator's own context.
- A visible **Open read-only authorization desk** link on the existing operator overview, plus a client navigation list in the desk. The ordinary client portal is unchanged for real client users.
- Explicit "Active execution locked" / "Dual-party consent not verified" / "Release not approved" notices. An approved assessment request is **not** automatically paired with a grant. A time-current grant is **not** proof of client/operator consent, at-use revocation or release authority.
- Per-request origin diagnostics distinguish a current client-admin/member account bound to the same client, an operator account, an unknown account, and a different-tenant account. This is a **current-account-role observation**, not signed evidence of the request's historical author.
- Stored grants with mismatched engagement/client lineage are flagged for review instead of being displayed as an acceptable grant record. Incomplete/invalid grant parsing is also marked for review.
- Output is HTML-escaped and capped at 60 records per section (up to 100 internally), with an explicit partial-view notice. All requests originate from the server's existing authenticated store; there are no user-controlled SQL fragments or write routes on the desk.

The desk is available **only** when explicitly running the guarded factory/launcher described above; ordinary LightUp entrypoints are unaffected. It introduces no new database schema and does not modify existing assessment approval handlers, domain methods or source-owned web handlers.

### What the operator can do

1. Sign in to the guarded LightUp web shell using the existing operator account.
2. Open **Authorization desk** from the operator overview and select a client.
3. Investigate requests whose current requester account is an operator, missing, or attached to another tenant.
4. Use the existing **Assessments** screen to perform authorized review. Do not treat the desk's informational badges as permission for real target interaction.

**No deployment, release promotion or execution authorization is implied.** This opt-in screen cannot grant or revoke consent and cannot run tools.

## Tenant-isolated assessment request receipts

The guarded portal additionally contains a **Request receipts** section, listing up to 30 newest saved requests with links to:

`GET /portal/<client_id>/requests/<request_id>`

This new **read-only** WSGI handler displays request ID, status, requested assets, requested mode/risk, submission timestamp, available decision timestamp and HTML-escaped client notes. It explicitly says that the receipt is **not** an authorization grant or verified client consent. It does not create or edit any grants, sessions, assessment requests or approvals.

The receipt is looked up via the existing `DomainStore.get_assessment_request` and a tenant-scoped portal read context. A client session for another client is denied by the dispatcher/domain checks; operators retain read-only cross-client portal visibility. The link list is bounded with an explicit truncation notice.

This feature is part of the **opt-in guarded** web variant only, so it does not change the active source owner for the original webapp or its route list.

## Authenticated JSON request status (read-only integration)

The guarded client receipt page links to:

`GET /api/v1/portal/<client_id>/requests/<request_id>`

This endpoint uses existing session authentication and the portal access policy, then rechecks tenant/request lineage directly through `DomainStore.get_assessment_request`. It returns `application/json` with the schema `lightup.portal-request-receipt.v1`.

The response contains request ID, client ID, status, requested mode/risk, timestamp fields and up to 80 requested assets. It **does not include** client free-text notes, credentials, evidence, signed consent, grant identifiers or secrets. Asset overflow is explicit. Missing, mismatched and malformed receipts all use the same generic 404 shape. Existing HTTP no-store, content-type protection and restrictive CSP headers apply.

The stable disposition is always `RECORD_ONLY`. It intentionally has the following fixed denial flags:

```json
{
  "execution_authorized": false,
  "client_consent_verified": false,
  "operator_consent_verified": false,
  "grant_bound": false,
  "release_approved": false
}
```

This contract is suitable for displaying *request status* in a separate authenticated client interface. It is **never** a token permitting real-target work and does not replace authenticated separate client/operator consent or a live grant/revocation check.

## Request inbox, operator work queue and review detail

The same opt-in WSGI product now supports these **read-only** routes in addition to the prior client receipt and operator desk:

| Route | Access | Product behavior |
|---|---|---|
| `GET /authorization-desk/queue/pending` | Operator session | Filter the desk to submitted / under-review requests |
| `GET /authorization-desk/queue/decided` | Operator session | Filter the desk to requests with a recorded decision |
| `GET /authorization-desk/requests/<request_id>` | Operator session | Read a complete request dossier, including risk, asset scope, notes and requester-account observation; no approve/reject button or automatic decision |
| `GET /api/v1/operator/authorization-queue` | Operator session only | A bounded pending-review JSON list with links to the dossiers |
| `GET /api/v1/portal/<client_id>/requests` | Signed-in tenant-bound client or operator reader | A bounded list of that tenant's request status records and receipt URLs |

The operator overview still links to the main desk. The desk has direct pending/decided filter links, client drilldowns and a link for each request to its detail. The request detail gives the operator a human-readable explanation of the current account-role observation **without** asserting that the person actually consented or had that role when they submitted the request.

The client portal shows legible request status cards (requested risk, creation time, first requested asset and status), and request receipts distinguish recorded, waiting, approved and rejected states. **An approved request is not a scan authorization**. They also link to the authenticated JSON status and tenant-scoped history.

### Machine-readable contract

The operator queue is `lightup.operator-request-inbox.v1`, `REVIEW_ONLY`. It lists pending requests up to 50 per snapshot and reports whether more exist. Client history is `lightup.portal-request-index.v1`, `RECORD_ONLY`, limited to 40 per snapshot. Both omit original free-text notes and sensitive session/evidence data. Request receipt IDs used in navigable URLs are bounded to canonical letters/digits/hyphens; malformed stored identities cause a generic denial, never a trusted or actionable link.

Both JSON index endpoints and the existing single-receipt endpoint return content type `application/json` and preserve LightUp's existing no-store/content-security protections. Unauthorized JSON callers receive JSON 401/403 rather than a successful HTML login redirect; mismatched tenants receive a generic 404 response. Both index schemas keep `execution_authorized`, `client_consent_verified`, `operator_consent_verified`, `grant_bound` and `release_approved` strictly `false`.

The API is an **information display contract only**. It never exports a grant or changes execution rights, the source-owned approval state machine, scope definitions, live revocation or client/operator consent.

### Current delivery and release gates

This is still an *opt-in web integration*, not the default installed LightUp application. The web source owner (#182) owns integration into the default routes. Under **INCUBATE M3/M7 PLAN/LAB ONLY / DRAFT HOLD** there must be no merge or deploy without independent security/privacy acceptance, separately authenticated client/operator consent with revocation at use, exact head required hosted/permanent named VPS CI, and an explicit human GO. No additional QA/regression suites were written or executed for this feature.

## Decision provenance review (issue #673)

The operator desk and request detail now report an additional **decision-lineage observation** for the specific original risk behind #673: the same account requesting and reviewing its own work.

- A stored decision in the `approved` / `rejected` state that references the **same `requested_by` and `decided_by` identity** is visibly flagged for human investigation.
- A decided record missing reviewer identity or decision timestamp is flagged.
- A pending record already carrying a reviewer identity or timestamp is flagged.
- A reviewer account that no longer exists or is not **currently** an operator is flagged.
- A present operator account is described as a **current-role observation**, never proof of role at decision time or of valid two-party consent.

The record remains unchanged by this view. Nothing here reverses approvals or grants execution authorization; actual immutable approval provenance, independent consent and at-use revocation need their existing separately owned source and security gates.

## Engagement-level grant/request dossier (issue #177 — observation only)

The operator authorization desk now links each engagement to an actual, authenticated record view:

- `GET /authorization-desk/engagements/<engagement_id>` renders a bounded read-only dossier with that engagement's recorded grants, time windows, requested assets, grant risk, lineage warnings and the client's assessment requests.
- `GET /api/v1/operator/engagements/<engagement_id>/review` returns the same view as `lightup.operator-engagement-review.v1` JSON, limited to 40 grants/requests per section; overflow is explicitly signalled.
- Both require an authenticated **operator**. The underlying `DomainStore` performs the original engagement and client lookups; neither a client session nor the URL can grant cross-tenant operator capabilities.
- Possible counterpart request links are displayed solely where the stored request is `APPROVED`, has `AUTHORIZED_ASSESSMENT` mode, has exactly overlapping raw asset strings and requests at least the grant's risk. These are **textual coincidences**, not canonical identity verification, independent client consent or a persisted request-to-grant reference. They never raise any authorization flag.
- Missing/mismatched client or engagement identifiers, unreadable scope, invalid windows, future and expired recorded windows, or missing corresponding requests are made visible for operator triage. There is no attempt to modify stored grants or enable live work.
- The JSON contract fixes `request_binding_verified`, `client_consent_verified`, `operator_consent_verified`, `revocation_checked_at_use`, `execution_authorized` and `release_approved` to **false**. The disposition is always `REVIEW_ONLY`.

**Critical boundary:** [issue #177](https://github.com/Zennay/Lightup/issues/177) requires the *domain* to persist and revalidate an immutable, approved-request-to-grant relationship. This UI makes absent provenance visible but **does not fix that domain invariant**. Existing owner [PR #1434](https://github.com/Zennay/Lightup/pull/1434) covers an independent offline review; no shared source or release paths are changed here.

All features stay in the explicit opt-in guarded WSGI variant. No scanning, real-world target contact, consent grant, active handler, QA suite or production deployment is introduced.

## Operator engagement follow-up queue

The opt-in operator desk links to `GET /authorization-desk/engagements/attention`, with a parallel `GET /api/v1/operator/engagements/attention` JSON view (`lightup.operator-engagement-attention.v1`).

The worklist displays up to 32 engagements per snapshot, combining their bounded read-only grant/request observations into actionable operator follow-up messages: no grant on record, mismatched persisted tenant/engagement identities, invalid/expired/future grant windows, absent *textually possible* approved requests, or a partial/incomplete record view. Every entry also explicitly needs an immutable request→grant link, separately authenticated client/operator consent and at-use revocation. Entries navigate directly to their own engagement dossiers.

The special route `/authorization-desk/engagements/attention` has a reserved name, distinct from canonical UUID engagement-detail routes. This prevents a name collision between the attention index and a requested engagement ID. No records are mutated, and every JSON authority flag is permanently false.

## Client-facing recorded scope transparency

New routes in the **opt-in guarded** portal:

- `GET /portal/<client_id>/scope-records` — understandable read-only scope records for a signed-in matching client, or a read-only operator visitor.
- `GET /api/v1/portal/<client_id>/scope-records` — matching `lightup.client-scope-records.v1` JSON for a tenant-bound client interface. Missing authentication returns JSON 401; a session for another tenant receives a generic JSON 404.

Clients can see which assessments are registered, time windows, recorded maximum risk, included/excluded assets and whether a window has expired. **The window observation is not an authorization decision.** Existing client portal pages link to this display. The feature never edits stored grants or requests.

Tenant-lineage enforcement is stricter than blindly trusting the current persisted-grant read method (see [issue #829](https://github.com/Zennay/Lightup/issues/829)): each displayed record must explicitly carry the requested client's own ID **and** its current engagement's ID, and must have a bounded, parseable scope and datetime window. If a stored grant does not meet those requirements, its content is **withheld** rather than exposed to a potentially wrong tenant. The UI reports that inconsistent records were withheld without revealing their details. Collections are bounded at 32 engagements and 48 grants each, and each scope lists up to 32 assets/exclusions; truncation is explicit.

The JSON disposition is fixed to `RECORD_ONLY`; its request-binding, client/operator consent, revocation-at-use, execution and release flags are permanently false. This is customer transparency, **not** verified client consent, an execution grant or a replacement for durable domain fixes. It is independent of the domain owner and does not modify existing authorization source.

## Implementation and release boundary

The new operator and client features change only files owned by the opt-in [PR #1566](https://github.com/Zennay/Lightup/pull/1566). The release remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD** until independent security/privacy review, live authorization with revocation, exact-head required CI and explicit human release approval. No QA suites, external target scans, production grant issuance or deployment are introduced.
