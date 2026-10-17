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
