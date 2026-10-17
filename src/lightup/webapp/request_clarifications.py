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
            if not as_operator:
                user = db.execute(
                    "SELECT role,client_id FROM users WHERE user_id=?",
                    (ctx.user_id,),
                ).fetchone()
                if (
                    user is None or user[0] != ctx.role.value
                    or user[1] != request.client_id
                ):
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
            "ORDER BY created_at ASC,message_id ASC LIMIT ?",
            (request_id, request.client_id, MAX_VISIBLE + 1),
        ).fetchall()
        total_row = db.execute(
            "SELECT COUNT(*) FROM assessment_clarifications "
            "WHERE request_id=? AND client_id=?",
            (request_id, request.client_id),
        ).fetchone()
    visible = rows[:MAX_VISIBLE]
    state = (
        "Awaiting client reply" if visible and visible[-1][3] == "question"
        else "Awaiting operator review" if visible else "No clarification yet"
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
                       operator: bool, action: str) -> str:
    cards = "".join(
        '<div class="card"><div class="row"><strong>'
        + ("Operator question" if item["kind"] == "question" else "Client reply")
        + '</strong><span class="meta">' + _e(item["created_at"])
        + '</span></div><p>' + _e(item["body"]).replace("\n", "<br>")
        + '</p></div>'
        for item in snapshot["messages"]
    ) or '<p class="empty">No questions or replies yet.</p>'
    can_write = snapshot["request_status"] in ("submitted", "under_review")
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


def client_thread_json(
    store: DomainStore, auth: AuthState, client_id: str, request_id: str,
) -> Response:
    try:
        snapshot = messages_for_request(store, auth, request_id, client_id=client_id)
    except (ClarificationDenied, KeyError, ValueError, TypeError):
        return Response('{"error":"conversation unavailable"}', "404 Not Found",
                        "application/json; charset=utf-8")
    return Response(
        json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")),
        content_type="application/json; charset=utf-8",
    )


def operator_thread_json(store: DomainStore, auth: AuthState, request_id: str) -> Response:
    if not auth.is_operator:
        return Response('{"error":"operator required"}', "403 Forbidden",
                        "application/json; charset=utf-8")
    try:
        snapshot = messages_for_request(store, auth, request_id)
    except (ClarificationDenied, KeyError, ValueError, TypeError):
        return Response('{"error":"conversation unavailable"}', "404 Not Found",
                        "application/json; charset=utf-8")
    return Response(
        json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")),
        content_type="application/json; charset=utf-8",
    )
