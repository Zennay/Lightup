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
| `GET /authorization-desk/requests/<request_id>` | Operator session | Read a request dossier with risk, asset scope, notes and requester provenance; where eligible, record an explicit guarded administrative approve/reject decision; no grant or scan authorization |
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

## Safe browser-side authorization decisions and grant freeze (issue #673 / #177)

The opt-in guarded web application now goes beyond read-only status screens by enforcing **real, server-side workflow restrictions** before its existing decision handlers are reached.

**Request approvals:**
- `POST /assessments/requests/<request_id>/decision` accepts only the literal `approve` or `reject`, not an ambiguous value silently mapped to rejection.
- Administrative `approve` requires an open request, `AUTHORIZED_ASSESSMENT` mode, client review risk 1–4, a bounded nonempty duplicate-free asset tuple, an active client, and an existing **current** `CLIENT_ADMIN`/`CLIENT_MEMBER` requester identity belonging to that same tenant. It rejects an operator-origin request or a request with pre-existing decision metadata.
- The approver may never approve their own request. Invalid requests may still be explicitly rejected to close bad historical records.
- The inherited operator assessment screen replaces unsafe **Approve** forms with an explanatory locked badge, while keeping a valid Reject action. The POST checks remain independently enforced and return HTTP `423 Locked` on unsafe approval. Legitimate administrative reviews still record `APPROVED` and redirect normally.
- An administrative `APPROVED` request does **not** grant execution or constitute historical client signature; current account role alone cannot prove who originally controlled the account.

**Risk elevations:**
- `POST /assessments/elevations/<approval_id>/decision` accepts only `approve` or `deny`. Approving additionally requires a pending record without prior decision metadata, a bounded 1–4 risk level, a nonempty bounded justification, a current genuine tenant-bound client requester, an engagement from the same tenant and an independent operator decision maker.
- Self-decisions are locked; the existing domain method's separate self-review check is left intact. Unsafe elevation buttons in the operator screen are replaced with locked explanatory notices rather than inviting an action the server must refuse. Explicit legitimate decisions continue through the existing domain method.

**Grant creation and legacy exposure:**
- `POST /engagements/<engagement_id>/grants` in this guarded opt-in app **always returns HTTP `423 Locked`**, regardless of form fields, until the real immutable approved-request/grant binding (#177), separate signed consent and at-use revocation are implemented in the domain and security authority surfaces.
- The operator client detail page removes the inherited grant-create forms. Previously stored time-current grants are labeled as **unverified records**, not valid scanning authority. Their underlying reference/approver/asset detail panel is withheld on that screen until persisted grant lineage is independently revalidated (#829); the dedicated operator authorization desk supports separately scoped read-only inspection.
- No new grants or execution permits are issued by this feature. This is a **guard only in the explicitly selected WSGI variant**, not a fix for direct `DomainStore` API callers or the default application. The domain issues #177 and #829, source-owner PR #182 and all security/CI/consent/release gates remain outstanding.

This change modifies only the opt-in portal's own module plus a new `authorization_controls.py`; existing source-owner approval handlers, domain, database schema, workflows and production deployment are unchanged. No QA or regression suites were added or run. Short source-compile and direct in-process functional inspections were used.

## Actionable guarded request dossier

The opt-in request dossier `GET /authorization-desk/requests/<request_id>` now provides the complete administrative workflow directly in the operator review screen:

- For an open, genuinely same-tenant client-origin request with valid bounded mode/risk/assets, show two explicit CSRF-protected POST forms: **Approve administrative request** and **Reject request**.
- If the server-side provenance guard finds a missing/mismatched requester, operator-originated request, already-recorded decision metadata, invalid mode, invalid risk or ambiguous asset scope, show **Approval blocked** and its concrete reason instead. The safe **Reject request** action remains to close malformed historical submissions.
- The server always repeats the authorization check inside `OperatorReadOnlyWebApp.decide_request`; the page is not a source of authority. A direct POST, altered form or stale bookmarked URL cannot bypass the same guard.
- These controls change **only** the stored administrative request status using the existing domain method. An `APPROVED` request never creates an execution grant or certifies actual written customer consent.

The default `LightUpWebApp` and domain API still require their independently owned security and request/grant-binding fixes before production use; the guarded WSGI variant remains opt-in and DRAFT/HOLD.

## Live client/operator clarification workflow (administrative only)

The guarded LightUp portal now supports a real **two-party request clarification conversation**. This is a usable product workflow for resolving missing client details without opening target access or issuing grants.

1. An authenticated operator opens an **open** request in `/authorization-desk/requests/<request_id>` and asks a bounded question using the CSRF-protected operator POST `/operator/requests/<request_id>/clarifications`.
2. A genuinely signed-in client of that request's tenant sees the question and its time in `/portal/<client_id>/requests/<request_id>`. Only while a question is awaiting a client reply can that same client's session submit a response to `POST /portal/<client_id>/requests/<request_id>/clarifications`. Operator-as-client masquerading is never used for writes.
3. The complete chronological thread is visible in each party's request detail. Its durable state is visible as **Awaiting client reply** or **Awaiting operator review** in both portals, the operator worklist and the existing single-request and request-index JSON.
4. Unanswered questions **block administrative request approval server-side** (423 Locked) as well as hiding the operator Approve action. Once an eligible client responds, the operator can perform the existing guarded *administrative* decision. Following approval/rejection, all thread POSTs stop accepting new messages (409 Conflict).
5. The operator gets a dedicated `GET /authorization-desk/clarifications` inbox and `GET /api/v1/operator/clarifications` status feed. Open conversations are grouped into **Needs operator follow-up** and **Waiting for client**, with links back to the proper request dossier. Clients see their own conversation state in their portal request cards.

### Authentication, storage and API boundaries

- The opt-in guarded WSGI factory initializes `assessment_clarifications` as a separate **additive SQLite table** in the existing `DomainStore.path`; original domain source, schema string and existing tables are not modified. Table-level FK references enforce the original request/client IDs. The append transaction uses `BEGIN IMMEDIATE` and checks the *current* pending request status and tenant lineage in the same write transaction; client replies additionally check the real client user's current DB role and tenant.
- Each record stores a UUID message ID, tenant/request IDs, **actual author account ID/role**, question/reply kind, UTC timestamp and up to 2,400 printable characters. The service accepts at most 200 messages per request; HTML is escaped and newlines remain readable. Latest 60 messages appear in chronological order with explicit partial-history notice (older messages are retained).
- JSON reads: `GET /api/v1/portal/<client_id>/requests/<request_id>/clarifications` and `GET /api/v1/operator/requests/<request_id>/clarifications`. Existing session and route access policies apply; the client route re-verifies matching tenant ownership. Output schema `lightup.request-clarifications.v1`, always `DISCUSSION_ONLY`, with consent/grant/execution flags permanently `false`. The queue JSON is `lightup.clarification-inbox.v1`, also `DISCUSSION_ONLY`.
- Request history clients and operator request inbox now show a bounded **clarification_state** badge; it is never interpreted as a signed approval or a grant. The operator clarification inbox deliberately omits message bodies, referring the reviewer to the authenticated request dossier.
- This is a planning discussion, not digitally signed proof of ownership, a client authorization letter, a legal consent record, or authority for active security scans. The existing independent two-party consent, immutable grant binding (#177), live revocation and release gates remain mandatory. No credentials or sensitive secrets should be pasted into these messages.

### Direct implementation inspection

Used connected zSSH in a disposable local SQLite checkout only (not a QA/regression suite). An operator question was saved and appeared in the client portal, blocked administrative approval (423), appeared as **waiting for client** in the operator JSON inbox; a genuine client reply was saved and moved the inbox to **waiting for operator**; the guarded administrative review subsequently returned 303. A different-tenant reply returned 403 and a post-decision reply returned 409. The JSON authority flags remained false and anonymous operator-inbox JSON returned 401. No real target interaction, scans, grant issuance, merge or deployment.
