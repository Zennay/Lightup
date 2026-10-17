"""Tenant-bound, durable assessment clarification thread for guarded LightUp.

This creates planning-only messages, never client consent, immutable signed
authorization, a grant, an approval, or a capability to contact targets.

The table lives alongside DomainStore's SQLite data in the same deployment DB;
the domain implementation and existing schema owner files remain untouched.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from ..domain import AccessContext, DomainStore, RequestStatus, Role
from .app import AuthState, Response, _e, _page

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessment_clarifications (
    message_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES assessment_requests(request_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    author_id TEXT NOT NULL,
    author_role TEXT NOT NULL CHECK(author_role IN ('operator','client_admin','client_member')),
    message_kind TEXT NOT NULL CHECK(message_kind IN ('question','reply')),
    message_body TEXT NOT NULL CHECK(length(message_body) BETWEEN 1 AND 2400),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS clarification_by_request
    ON assessment_clarifications(request_id, created_at, message_id);
"""
MAX_PER_REQUEST = 200
MAX_VISIBLE = 60
_ID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")


class ClarificationDenied(ValueError):
    """A clarification would cross an identity, state or size boundary."""


def _safe_id(raw: object) -> bool:
    return type(raw) is str and _ID.fullmatch(raw) is not None


def initialize_clarifications(store: DomainStore) -> None:
    """Idempotent opt-in migration; no mutation of the existing domain tables."""
    with sqlite3.connect(store.path, timeout=10) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript(_SCHEMA)


def _context(auth: AuthState) -> AccessContext:
    ctx = auth.context
    if type(ctx) is not AccessContext or type(ctx.role) is not Role:
        raise ClarificationDenied("Authenticated account required")
    if not _safe_id(ctx.user_id):
        raise ClarificationDenied("Account identity is malformed")
    return ctx


def _read_request(store: DomainStore, ctx: AccessContext, request_id: str):
    if not _safe_id(request_id):
        raise ClarificationDenied("Request identity is malformed")
    request = store.get_assessment_request(ctx, request_id)
    if not _safe_id(request.client_id):
        raise ClarificationDenied("Request client identity is malformed")
    return request


def _client_lineage(store: DomainStore, ctx: AccessContext, request) -> None:
    """A signed-in client must be linked to its own request's tenant."""
    if ctx.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER):
        raise ClarificationDenied("A real client account is required")
    if ctx.client_id != request.client_id:
        raise ClarificationDenied("Request belongs to a different client")
    # Existing signed-in sessions supply the actual ctx, never synthetic
    # _portal_context, which only serves operator read-only views.


def append_message(
    store: DomainStore, auth: AuthState, request_id: str, message: str,
    *, as_operator: bool,
) -> str:
    """Atomically append to an OPEN request, with a role-bound message kind.

    The request's current tenant, state, and persisted account are checked
    in the very same SQLite write transaction as the new message. Client
    messages cannot be posted using a synthetic operator-as-client context.
    """
    ctx = _context(auth)
    if not isinstance(message, str):
        raise ClarificationDenied("Clarification text is required")
    content = message.strip()
    if (
        not 1 <= len(content) <= 2400
        or any((ord(c) < 32 and c not in "\n\t") or ord(c) == 127 for c in content)
    ):
        raise ClarificationDenied("Message must contain 1–2400 readable characters")
    request = _read_request(store, ctx, request_id)
    if as_operator:
        if ctx.role is not Role.OPERATOR:
            raise ClarificationDenied("Only an operator can ask a question")
        kind = "question"
    else:
        _client_lineage(store, ctx, request)
        kind = "reply"
    message_id = str(uuid4())
    with sqlite3.connect(store.path, timeout=10, isolation_level=None) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute(
                "SELECT client_id,status FROM assessment_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if (
                row is None or row[0] != request.client_id
                or row[1] not in (
                    RequestStatus.SUBMITTED.value, RequestStatus.UNDER_REVIEW.value
                )
            ):
                raise ClarificationDenied(
                    "This request is closed or its client lineage changed"
                )
            # Validate the real account identity *inside the same write
            # transaction* for both sides of the discussion. A stale
            # session role or manufactured AccessContext cannot send a message.
            user = db.execute(
                "SELECT role,client_id FROM users WHERE user_id=?",
                (ctx.user_id,),
            ).fetchone()
            if user is None or user[0] != ctx.role.value:
                raise ClarificationDenied(
                    "Author account is absent or its role has changed"
                )
            if as_operator:
                if user[1] is not None:
                    raise ClarificationDenied(
                        "Operator account cannot be bound to a client"
                    )
            elif user[1] != request.client_id:
                raise ClarificationDenied(
                    "Client account no longer belongs to this tenant"
                )
            count = db.execute(
                "SELECT COUNT(*) FROM assessment_clarifications WHERE request_id=?",
                (request_id,),
            ).fetchone()[0]
            if count >= MAX_PER_REQUEST:
                raise ClarificationDenied(
                    "Conversation is full; request a new assessment instead"
                )
            last = db.execute(
                "SELECT message_kind FROM assessment_clarifications "
                "WHERE request_id=? ORDER BY created_at DESC,message_id DESC LIMIT 1",
                (request_id,),
            ).fetchone()
            # A client can only respond after an operator asks a question.
            # Operators may ask a follow-up without requiring a client reply.
            if not as_operator and (last is None or last[0] != "question"):
                raise ClarificationDenied("There is no operator question awaiting a reply")
            db.execute(
                "INSERT INTO assessment_clarifications"
                "(message_id,request_id,client_id,author_id,author_role,"
                "message_kind,message_body,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    message_id, request_id, request.client_id, ctx.user_id,
                    ctx.role.value, kind, content,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return message_id


def messages_for_request(
    store: DomainStore, auth: AuthState, request_id: str,
    *, client_id: str | None = None,
) -> dict:
    """Return a bounded tenant-checked read with explicit truncation."""
    ctx = _context(auth)
    request = _read_request(store, ctx, request_id)
    if client_id is not None and (not _safe_id(client_id) or client_id != request.client_id):
        raise ClarificationDenied("Request is not part of this client portal")
    if ctx.role is not Role.OPERATOR:
        _client_lineage(store, ctx, request)
    with sqlite3.connect(store.path, timeout=10) as db:
        db.execute("PRAGMA foreign_keys=ON")
        rows = db.execute(
            "SELECT message_id,author_id,author_role,message_kind,message_body,created_at "
            "FROM assessment_clarifications WHERE request_id=? AND client_id=? "
            "ORDER BY created_at DESC,message_id DESC LIMIT ?",
            (request_id, request.client_id, MAX_VISIBLE + 1),
        ).fetchall()
        total_row = db.execute(
            "SELECT COUNT(*) FROM assessment_clarifications "
            "WHERE request_id=? AND client_id=?",
            (request_id, request.client_id),
        ).fetchone()
    # Display the newest conversation window in chronological order. Earlier
    # messages may be omitted, but the waiting state always uses the newest
    # durable row, never an outdated first-page record.
    latest_kind = rows[0][3] if rows else None
    visible = list(reversed(rows[:MAX_VISIBLE]))
    state = (
        "Awaiting client reply" if latest_kind == "question"
        else "Awaiting operator review" if latest_kind == "reply"
        else "No clarification yet"
    )
    return {
        "schema": "lightup.request-clarifications.v1",
        "disposition": "DISCUSSION_ONLY",
        "request_id": request.request_id,
        "client_id": request.client_id,
        "request_status": request.status.value,
        "awaiting": state,
        "partial": total_row[0] > MAX_VISIBLE,
        "messages": [
            {
                "id": row[0], "author_role": row[2], "kind": row[3],
                "body": row[4], "created_at": row[5],
            }
            for row in visible
        ],
        "consent_verified": False,
        "grant_bound": False,
        "execution_authorized": False,
        "notice": (
            "Messages are administrative clarifications, not signed customer "
            "consent, an approved scope or permission to scan."
        ),
    }


def render_thread_html(snapshot: dict, auth: AuthState, *,
                       operator: bool, action: str,
                       allow_post: bool = True) -> str:
    cards = "".join(
        '<div class="card"><div class="row"><strong>'
        + ("Operator question" if item["kind"] == "question" else "Client reply")
        + '</strong><span class="meta">' + _e(item["created_at"])
        + '</span></div><p>' + _e(item["body"]).replace("\n", "<br>")
        + '</p></div>'
        for item in snapshot["messages"]
    ) or '<p class="empty">No questions or replies yet.</p>'
    can_write = allow_post and snapshot["request_status"] in (
        "submitted", "under_review"
    )
    if not operator and snapshot["awaiting"] != "Awaiting client reply":
        can_write = False
    if can_write:
        form = (
            '<div class="card"><form method="post" action="' + _e(action)
            + '"><input type="hidden" name="csrf" value="' + _e(auth.csrf or "")
            + '"><label>'
            + ("Ask the client for clarification" if operator else
               "Reply to the operator question")
            + '</label><textarea name="message" maxlength="2400" '
            'rows="4" required></textarea>'
            '<p class="meta">Administrative discussion only. Do not paste '
            'credentials, secrets or real authorization documents here. '
            'Messages do not grant testing permissions.</p>'
            '<button>Send message</button></form></div>'
        )
    else:
        form = (
            '<p class="meta">Operator client-portal browsing is strictly '
            'read-only. Ask questions from the operator request dossier.</p>'
            if not allow_post else
            '<p class="meta">Replies are not currently available. '
            'A request must be open and a client reply requires an '
            'unanswered operator question.</p>'
        )
    return (
        '<h2>Assessment clarifications</h2>'
        '<div class="card"><span class="badge lock">Discussion only</span>'
        '<p class="meta">' + _e(snapshot["awaiting"])
        + '. Written messages do not establish verified client consent '
        'or approval to use security tools.</p></div>'
        + ("<p class=\"meta\">Partial thread shown.</p>"
           if snapshot["partial"] else "")
        + cards + form
    )


def thread_states(
    store: DomainStore, auth: AuthState, request_ids: list[str],
    *, client_id: str | None = None,
) -> dict[str, str]:
    """Single bounded DB read for inbox badges; no message bodies disclosed.

    A badge is a planning reminder, not verified consent or reviewer approval.
    """
    ctx = _context(auth)
    if len(request_ids) > 120 or any(not _safe_id(i) for i in request_ids):
        raise ClarificationDenied("Invalid or oversized request list")
    if client_id is not None:
        if not _safe_id(client_id):
            raise ClarificationDenied("Malformed client identity")
        if ctx.role is not Role.OPERATOR and ctx.client_id != client_id:
            raise ClarificationDenied("Another client's inbox is unavailable")
    if not request_ids:
        return {}
    # Per-request latest message kind only: no notes or author identity leave
    # this service, and each message is constrained to its stored tenant ID.
    placeholders = ",".join("?" for _ in request_ids)
    with sqlite3.connect(store.path, timeout=10) as db:
        rows = db.execute(
            "SELECT m.request_id,m.client_id,m.message_kind "
            "FROM assessment_clarifications m "
            "JOIN assessment_requests r ON m.request_id=r.request_id "
            "WHERE m.request_id IN (" + placeholders + ") "
            "AND m.client_id=r.client_id "
            "AND NOT EXISTS("
            "SELECT 1 FROM assessment_clarifications newer "
            "WHERE newer.request_id=m.request_id AND newer.client_id=m.client_id "
            "AND (newer.created_at > m.created_at OR "
            "(newer.created_at=m.created_at AND newer.message_id>m.message_id)))",
            tuple(request_ids),
        ).fetchall()
    results = {}
    for req_id, stored_client, kind in rows:
        if client_id is not None and stored_client != client_id:
            continue
        if ctx.role is not Role.OPERATOR and stored_client != ctx.client_id:
            continue
        results[req_id] = (
            "Awaiting client reply" if kind == "question"
            else "Awaiting operator review" if kind == "reply"
            else "Unknown message state"
        )
    return results


def client_thread_json(
    store: DomainStore, auth: AuthState, client_id: str, request_id: str,
) -> Response:
    try:
        snapshot = messages_for_request(store, auth, request_id, client_id=client_id)
    except (ClarificationDenied, KeyError, ValueError, TypeError):
        return Response('{"error":"conversation unavailable"}', "404 Not Found",
                        "application/json; charset=utf-8")
    payload = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > 128 * 1024:
        return Response(
            '{"error":"conversation too large to export"}',
            status="413 Payload Too Large",
            content_type="application/json; charset=utf-8",
        )
    return Response(payload, content_type="application/json; charset=utf-8")


def operator_thread_json(store: DomainStore, auth: AuthState, request_id: str) -> Response:
    if not auth.is_operator:
        return Response('{"error":"operator required"}', "403 Forbidden",
                        "application/json; charset=utf-8")
    try:
        snapshot = messages_for_request(store, auth, request_id)
    except (ClarificationDenied, KeyError, ValueError, TypeError):
        return Response('{"error":"conversation unavailable"}', "404 Not Found",
                        "application/json; charset=utf-8")
    payload = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > 128 * 1024:
        return Response(
            '{"error":"conversation too large to export"}',
            status="413 Payload Too Large",
            content_type="application/json; charset=utf-8",
        )
    return Response(payload, content_type="application/json; charset=utf-8")


def clarification_inbox_snapshot(
    store: DomainStore, auth: AuthState, *, limit: int = 60,
) -> dict:
    """Current open request threads, grouped by who should act next.

    The index is not a consent or signature register; it contains no message
    bodies and cannot create or decide an assessment request.
    """
    ctx = _context(auth)
    if ctx.role is not Role.OPERATOR:
        raise ClarificationDenied("A real operator account is required")
    count = max(1, min(60, limit))
    with sqlite3.connect(store.path, timeout=10) as db:
        db.execute("PRAGMA foreign_keys=ON")
        rows = db.execute(
            "SELECT m.request_id,m.client_id,m.message_kind,m.created_at "
            "FROM assessment_clarifications m "
            "JOIN assessment_requests r ON r.request_id=m.request_id "
            "AND r.client_id=m.client_id "
            "WHERE r.status IN ('submitted','under_review') "
            "AND NOT EXISTS("
            " SELECT 1 FROM assessment_clarifications newer "
            " WHERE newer.request_id=m.request_id AND newer.client_id=m.client_id "
            " AND (newer.created_at > m.created_at OR "
            " (newer.created_at=m.created_at AND newer.message_id>m.message_id))"
            ") ORDER BY m.created_at DESC,m.message_id DESC LIMIT ?",
            (count + 1,),
        ).fetchall()
    items = []
    for req_id, client_id, kind, latest_at in rows[:count]:
        if not _safe_id(req_id) or not _safe_id(client_id):
            raise ClarificationDenied("Stored thread identity is invalid")
        request = _read_request(store, ctx, req_id)
        if request.client_id != client_id:
            raise ClarificationDenied("Inconsistent request tenant")
        if kind not in ("question", "reply"):
            raise ClarificationDenied("Stored conversation kind is invalid")
        items.append({
            "request_id": req_id,
            "client_id": client_id,
            "waiting_for": "client" if kind == "question" else "operator",
            "last_message_at": latest_at,
            "review_url": "/authorization-desk/requests/" + req_id,
        })
    return {
        "schema": "lightup.clarification-inbox.v1",
        "disposition": "DISCUSSION_ONLY",
        "items": items,
        "partial": len(rows) > count,
        "execution_authorized": False,
        "consent_verified": False,
        "grant_bound": False,
        "notice": "This queue is for administrative clarification only.",
    }


def operator_clarification_inbox_page(
    store: DomainStore, auth: AuthState,
) -> Response:
    if not auth.is_operator:
        return Response("<h1>Operator required</h1>", status="403 Forbidden")
    try:
        inbox = clarification_inbox_snapshot(store, auth)
    except (ClarificationDenied, KeyError, ValueError, TypeError):
        return Response("<h1>Clarification inbox unavailable</h1>",
                        status="503 Service Unavailable")
    needs_operator = [
        item for item in inbox["items"] if item["waiting_for"] == "operator"
    ]
    waiting_client = [
        item for item in inbox["items"] if item["waiting_for"] == "client"
    ]

    def cards(items: list[dict]) -> str:
        return "".join(
            '<div class="card"><strong>Request ' + _e(item["request_id"])
            + '</strong><p class="meta">Client: ' + _e(item["client_id"])
            + '<br>Last activity: ' + _e(item["last_message_at"])
            + '</p><a href="' + _e(item["review_url"])
            + '">Open conversation and request dossier →</a></div>'
            for item in items
        ) or '<p class="empty">No open clarifications in this group.</p>'

    body = (
        '<h1>Clarification inbox</h1>'
        '<p class="sub">Follow up on pending client discussions before '
        'administrative review. No grant or scan is authorized here.</p>'
        '<div class="card"><span class="badge lock">Discussion only</span>'
        '<p class="meta">Client replies are not signed consent; approval '
        'still requires independently verified authority and domain gates.</p>'
        '<a href="/authorization-desk">Authorization desk</a> · '
        '<a href="/api/v1/operator/clarifications">Read-only JSON</a></div>'
        + ('<p class="meta">Showing only the most recent threads.</p>'
           if inbox["partial"] else "")
        + '<h2>Needs operator follow-up (' + str(len(needs_operator)) + ')</h2>'
        + cards(needs_operator)
        + '<h2>Waiting for client (' + str(len(waiting_client)) + ')</h2>'
        + cards(waiting_client)
    )
    return Response(_page("LightUp — Clarification inbox", "assessments",
                          body, auth))


def operator_clarification_inbox_json(
    store: DomainStore, auth: AuthState,
) -> Response:
    if not auth.is_operator:
        return Response('{"error":"operator required"}', status="403 Forbidden",
                        content_type="application/json; charset=utf-8")
    try:
        data = clarification_inbox_snapshot(store, auth)
    except (ClarificationDenied, KeyError, ValueError, TypeError):
        return Response('{"error":"clarification inbox unavailable"}',
                        status="503 Service Unavailable",
                        content_type="application/json; charset=utf-8")
    return Response(
        json.dumps(data, ensure_ascii=True, separators=(",", ":")),
        content_type="application/json; charset=utf-8",
    )
