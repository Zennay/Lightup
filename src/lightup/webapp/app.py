"""LightUp web shell: operator/admin dashboard + client portal.

Deliberately dependency-free (stdlib WSGI) so the skeleton runs anywhere the
tests run. The UI follows ``docs/ui-principles.md``:

- calm, minimal, responsive, one primary action per screen;
- progressive disclosure: status first, details behind ``<details>``;
- clients see Finding → Impact → Fix → Retest, never scanner output;
- active testing is visibly **Locked** everywhere — this build contains no
  real-target execution path and no route can trigger one.

Security posture of this phase:

- every page requires a signed-in session (cookie ``lightup_session``, stored
  server-side as a SHA-256 hash with an expiry);
- admin pages require an operator session; the portal requires a session of
  that client (or an operator) — on top of the tenant isolation that
  :mod:`lightup.domain` enforces regardless of the UI;
- every POST requires the session's CSRF token;
- all dynamic output is HTML-escaped and responses carry a restrictive CSP;
- the server still binds to loopback only; the cookie is ``HttpOnly`` and
  ``SameSite=Strict`` (no ``Secure`` flag yet: the dev shell speaks plain
  http on loopback — TLS termination is part of a later deployment package).

Bootstrap the first account with ``lightup create-operator``.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Callable, Iterable
from .forms import FormError, read_form
from .security import RequestRejected, WebSecurity

from ..domain import (
    AccessContext,
    AccountLockedError,
    DomainStore,
    ProspectStatus,
    RequestStatus,
    Role,
    TenantIsolationError,
)
from ..engagements import AssessmentMode, RiskLevel
from ..models import RetestStatus

SESSION_COOKIE = "lightup_session"

_RISK_LABELS = {
    RiskLevel.ANALYSIS_ONLY: "0 — Analysis only",
    RiskLevel.PASSIVE: "1 — Passive",
    RiskLevel.LOW_IMPACT: "2 — Low impact",
    RiskLevel.STANDARD: "3 — Standard",
    RiskLevel.ELEVATED: "4 — Elevated",
    RiskLevel.DESTRUCTIVE_LAB_ONLY: "5 — Destructive (lab only)",
}

_AUTH_REVIEW_ACTIONS = {
    "review_client_requests": "Client requests awaiting review",
    "review_risk_decisions": "Risk elevations awaiting review",
    "review_unrestricted_grants": "Unrestricted legacy scope records",
    "review_expired_grants": "Expired request-bound grant windows",
    "review_future_grants": "Future-dated grant windows",
    "review_missing_grants": "Engagements without request-bound grants",
}

_CSS = """
:root { --bg:#f6f7f8; --card:#ffffff; --ink:#1c2430; --muted:#5d6b7a;
        --line:#e3e7ea; --accent:#2f6f5f; --warn:#8a5a19; --lock:#7a2e2e; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
       font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }
a { color:var(--accent); text-decoration:none; }
header { background:var(--card); border-bottom:1px solid var(--line); }
.wrap { max-width:960px; margin:0 auto; padding:0 20px; }
header .wrap { display:flex; flex-wrap:wrap; align-items:baseline; gap:18px;
               padding-top:14px; padding-bottom:14px; }
.brand { font-weight:650; letter-spacing:.02em; }
nav { display:flex; gap:14px; flex-wrap:wrap; align-items:baseline; }
nav a { color:var(--muted); padding:2px 0; }
nav a.active { color:var(--ink); border-bottom:2px solid var(--accent); }
nav form { display:inline; }
nav button { background:none; border:0; color:var(--muted); cursor:pointer;
             font:inherit; padding:0; }
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,
textarea:focus-visible { outline:3px solid var(--accent); outline-offset:3px; }
button,input:not([type="hidden"]):not([type="checkbox"]),select { min-height:44px; }
input[type="checkbox"] { width:auto; min-height:auto; margin:0; }
label.review-ack { display:flex; align-items:flex-start; gap:10px; margin:12px 0; }
main { padding:28px 0 64px; }
h1 { font-size:1.35rem; margin:0 0 4px; }
h2 { font-size:1.05rem; margin:28px 0 10px; }
.sub { color:var(--muted); margin:0 0 24px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px;
        padding:16px 18px; margin:0 0 14px; }
.grid { display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); }
.kpi { font-size:1.6rem; font-weight:650; }
.kpi-label { color:var(--muted); font-size:.85rem; }
.badge { display:inline-block; border-radius:999px; padding:1px 10px;
         font-size:.78rem; border:1px solid var(--line); color:var(--muted); }
.badge.lock { color:var(--lock); border-color:var(--lock); }
.badge.ok { color:var(--accent); border-color:var(--accent); }
.badge.warn { color:var(--warn); border-color:var(--warn); }
details { margin-top:10px; }
summary { cursor:pointer; color:var(--muted); }
.meta { color:var(--muted); font-size:.85rem; }
form.inline { display:inline; }
button { background:var(--accent); color:#fff; border:0; border-radius:8px;
         padding:7px 14px; font-size:.9rem; cursor:pointer; }
button.secondary { background:transparent; color:var(--muted);
                   border:1px solid var(--line); }
input,select,textarea { width:100%; padding:8px 10px; margin:4px 0 12px;
         border:1px solid var(--line); border-radius:8px; font:inherit;
         background:#fff; color:var(--ink); }
label { font-size:.85rem; color:var(--muted); }
.empty { color:var(--muted); font-style:italic; }
.row { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap;
       align-items:baseline; }
.auth { max-width:380px; margin:8vh auto 0; }
.error { color:var(--lock); font-size:.9rem; }
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _risk(level: RiskLevel) -> str:
    return _e(_RISK_LABELS[level])


def _request_progress(status: RequestStatus) -> list[dict[str, str]]:
    """Human-readable stages; never infer a live grant or activation."""
    if type(status) is not RequestStatus:
        raise ValueError("request progress requires an original persisted status")
    reviewed = {
        RequestStatus.SUBMITTED: ("AWAITING_REVIEW", "An independent operator must review this request."),
        RequestStatus.UNDER_REVIEW: ("UNDER_REVIEW", "An independent operator is reviewing this request."),
        RequestStatus.APPROVED: ("REQUEST_APPROVED_ONLY", "This decision is not a scope grant or scan permission."),
        RequestStatus.REJECTED: ("REQUEST_REJECTED", "This request cannot be used to issue a scope grant."),
    }[status]
    rejected = status is RequestStatus.REJECTED
    return [
        {
            "code": "CLIENT_SUBMISSION", "label": "Client request",
            "state": "RECORDED",
            "explanation": "Requested systems and risk are recorded; ownership is not independently verified.",
        },
        {
            "code": "INDEPENDENT_OPERATOR_REVIEW", "label": "Human decision",
            "state": reviewed[0], "explanation": reviewed[1],
        },
        {
            "code": "REQUEST_BOUND_SCOPE", "label": "Recorded scope and risk limits",
            "state": "BLOCKED_BY_REJECTION" if rejected else "CHECK_SEPARATELY",
            "explanation": (
                "This rejected request cannot support a scope grant. "
                "A new client-origin request needs a new independent review."
                if rejected else
                "A grant for a particular engagement is never inferred from this receipt."
            ),
        },
        {
            "code": "CLIENT_CONSENT_AND_REVOCATION", "label": "Current consent and revocation",
            "state": "NOT_APPLICABLE_TO_REJECTED_REQUEST" if rejected else "NOT_VERIFIED",
            "explanation": (
                "No consent or revocation check can rehabilitate this rejected request."
                if rejected else
                "Separate client consent and a revocation check at use are still required."
            ),
        },
        {
            "code": "HUMAN_GO_AND_EXECUTION", "label": "Human go and testing",
            "state": "LOCKED",
            "explanation": "No scan or capability activation is available in this plan/lab build.",
        },
    ]


@dataclass(frozen=True)
class AuthState:
    context: AccessContext | None
    csrf: str | None
    session_token: str | None = field(default=None, repr=False, compare=False)

    @property
    def signed_in(self) -> bool:
        return self.context is not None

    @property
    def is_operator(self) -> bool:
        return self.context is not None and self.context.is_operator


ANONYMOUS = AuthState(None, None)


class Response:
    def __init__(self, body: str, status: str = "200 OK",
                 content_type: str = "text/html; charset=utf-8",
                 extra_headers: list[tuple[str, str]] | None = None):
        self.status = status
        self.body = body.encode("utf-8")
        self.headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(self.body))),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
             "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
            ("X-Frame-Options", "DENY"),
            ("Cache-Control", "no-store"),
        ] + (extra_headers or [])


def _redirect(location: str, extra_headers: list[tuple[str, str]] | None = None) -> Response:
    return Response("", status="303 See Other",
                    extra_headers=[("Location", location)] + (extra_headers or []))


def _session_cookie(value: str, clear: bool = False, secure: bool = False) -> tuple[str, str]:
    attrs = "Path=/; HttpOnly; SameSite=Strict"
    if secure:
        attrs += "; Secure"
    if clear:
        return ("Set-Cookie", f"{SESSION_COOKIE}=; {attrs}; Max-Age=0")
    return ("Set-Cookie", f"{SESSION_COOKIE}={value}; {attrs}")


def _page(title: str, nav: str, body: str, auth: AuthState,
          portal_client: str | None = None) -> str:
    logout = ""
    if auth.signed_in and auth.csrf:
        logout = (
            f'<form method="post" action="/logout">'
            f'<input type="hidden" name="csrf" value="{_e(auth.csrf)}">'
            "<button>Sign out</button></form>"
        )
    if portal_client is None:
        links = [("overview", "/", "Overview"), ("discovery", "/discovery", "Discovery"),
                 ("clients", "/clients", "Clients"), ("assessments", "/assessments", "Assessments")]
        brand = "LightUp — Operator"
    else:
        base = f"/portal/{portal_client}"
        links = [
            ("portal", base, "Overview"),
            ("requests", base + "/requests", "Requests"),
            ("scope", base + "/authorization-plan", "Scope & safety"),
        ]
        brand = "LightUp — Client portal"
    nav_html = "".join(
        f'<a href="{href}" class="{"active" if key == nav else ""}">{label}</a>'
        for key, href, label in links
    ) + logout
    if nav == "login":
        nav_html = ""
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>"
        f"<header><div class=\"wrap\"><span class=\"brand\">{_e(brand)}</span>"
        f"<nav>{nav_html}</nav></div></header>"
        f"<main><div class=\"wrap\">{body}</div></main></body></html>"
    )


class LightUpWebApp:
    def __init__(self, store: DomainStore, security: WebSecurity | None = None):
        self.store = store
        self.security = security or WebSecurity()
        # access: "public" (login only), "operator", or "portal" (that client
        # or an operator). The access level is enforced in dispatch, before
        # any handler runs; handlers additionally act through the session's
        # own AccessContext, so the domain layer re-checks everything.
        self.routes: list[tuple[str, re.Pattern[str], Callable, str]] = [
            ("GET", re.compile(r"^/login$"), self.login_page, "public"),
            ("POST", re.compile(r"^/login$"), self.login_submit, "public"),
            ("POST", re.compile(r"^/logout$"), self.logout, "portal"),
            ("GET", re.compile(r"^/$"), self.overview, "operator"),
            ("GET", re.compile(r"^/authorization-overview\.json$"),
             self.authorization_overview_json, "operator"),
            ("GET", re.compile(r"^/authorization-reviews(?:/(?P<kind>[\w-]+))?$"),
             self.authorization_review_worklist, "operator"),
            ("GET", re.compile(r"^/authorization-reviews\.csv$"),
             self.authorization_review_worklist_csv, "operator"),
            ("GET", re.compile(r"^/authorization-reviews/(?P<kind>[\w-]+)\.csv$"),
             self.authorization_review_worklist_csv, "operator"),
            ("GET", re.compile(r"^/authorization-reviews\.records\.csv$"),
             self.authorization_review_records_csv, "operator"),
            ("GET", re.compile(r"^/authorization-reviews/(?P<kind>[\w-]+)\.records\.csv$"),
             self.authorization_review_records_csv, "operator"),
            ("GET", re.compile(r"^/discovery$"), self.discovery, "operator"),
            ("POST", re.compile(r"^/discovery/prospects$"), self.add_prospect, "operator"),
            ("POST", re.compile(r"^/discovery/prospects/(?P<prospect_id>[\w-]+)/status$"),
             self.prospect_status, "operator"),
            ("GET", re.compile(r"^/clients$"), self.clients, "operator"),
            ("POST", re.compile(r"^/clients$"), self.create_client, "operator"),
            ("GET", re.compile(r"^/clients/(?P<client_id>[\w-]+)$"), self.client_detail,
             "operator"),
            ("GET", re.compile(r"^/clients/(?P<client_id>[\w-]+)/authorization-plan$"),
             self.authorization_plan, "operator"),
            ("GET", re.compile(r"^/clients/(?P<client_id>[\w-]+)/authorization-plan.json$"),
             self.authorization_plan_json, "operator"),
            ("POST", re.compile(r"^/clients/(?P<client_id>[\w-]+)/engagements$"),
             self.create_engagement, "operator"),
            ("POST", re.compile(r"^/engagements/(?P<engagement_id>[\w-]+)/grants$"),
             self.record_grant, "operator"),
            ("GET", re.compile(r"^/assessments$"), self.assessments, "operator"),
            ("GET", re.compile(r"^/assessments/requests/(?P<request_id>[\w-]+)/review$"),
             self.review_request_page, "operator"),
            ("GET", re.compile(r"^/assessments/elevations/(?P<approval_id>[\w-]+)/review$"),
             self.review_elevation_page, "operator"),
            ("POST", re.compile(r"^/assessments/requests/(?P<request_id>[\w-]+)/decision$"),
             self.decide_request, "operator"),
            ("POST", re.compile(r"^/assessments/elevations/(?P<approval_id>[\w-]+)/decision$"),
             self.decide_elevation, "operator"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)$"), self.portal, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests$"),
             self.portal_requests, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests\.json$"),
             self.portal_requests_json, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/authorization-plan$"),
             self.portal_authorization_plan, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/authorization-plan.json$"),
             self.portal_authorization_plan_json, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests/(?P<request_id>[\w-]+)$"),
             self.portal_request_receipt, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests/(?P<request_id>[\w-]+)\.json$"),
             self.portal_request_receipt_json, "portal"),
            ("POST", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests/preview$"),
             self.portal_preview_request, "portal"),
            ("POST", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests$"),
             self.portal_submit_request, "portal"),
        ]

    # -- WSGI ---------------------------------------------------------------

    def __call__(self, environ, start_response) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/") or "/"
        try:
            self.security.validate(environ)
            form = read_form(environ) if method == "POST" else {}
        except RequestRejected:
            response = Response("<h1>Request rejected</h1>", status="403 Forbidden")
        except FormError as exc:
            response = Response("<h1>Invalid form request</h1>", status=exc.status)
        else:
            auth = self._authenticate(environ)
            response = self._dispatch(method, path, form, auth)
        if self.security.production:
            response.headers.append(("Strict-Transport-Security", "max-age=31536000"))
        start_response(response.status, response.headers)
        return [response.body]

    def _authenticate(self, environ) -> AuthState:
        cookie = SimpleCookie()
        try:
            cookie.load(environ.get("HTTP_COOKIE", ""))
        except Exception:
            return ANONYMOUS
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is None:
            return ANONYMOUS
        resolved = self.store.session_context(morsel.value)
        if resolved is None:
            return ANONYMOUS
        context, csrf = resolved
        return AuthState(context, csrf, morsel.value)

    def _dispatch(self, method: str, path: str, form: dict[str, str],
                  auth: AuthState) -> Response:
        for route_method, pattern, handler, access in self.routes:
            match = pattern.match(path)
            if not match or route_method != method:
                continue
            params = match.groupdict()

            if access != "public":
                if not auth.signed_in:
                    return _redirect("/login")
                if method == "POST" and form.get("csrf") != auth.csrf:
                    return Response(_page("Forbidden", "", "<h1>Invalid CSRF token</h1>",
                                          auth), status="403 Forbidden")
                if access == "operator" and not auth.is_operator:
                    return Response(_page("Forbidden", "", "<h1>Operator access required</h1>",
                                          auth), status="403 Forbidden")
                if access == "portal" and not auth.is_operator:
                    wanted = params.get("client_id")
                    if wanted is not None and auth.context.client_id != wanted:
                        return Response(_page("Forbidden", "", "<h1>Forbidden</h1>", auth),
                                        status="403 Forbidden")
            try:
                return handler(auth=auth, form=form, **params)
            except TenantIsolationError:
                return Response(_page("Forbidden", "", "<h1>Forbidden</h1>", auth),
                                status="403 Forbidden")
            except (KeyError, ValueError):
                # Domain exceptions can include client-controlled identifiers,
                # grant references or database field content. Never echo them.
                body = ("<h1>Request failed</h1>"
                        "<p class=\"sub\">The request could not be processed. "
                        "Check the information and try again.</p>")
                return Response(_page("Error", "", body, auth), status="400 Bad Request")
        return Response(_page("Not found", "", "<h1>Not found</h1>", ANONYMOUS),
                        status="404 Not Found")

    @staticmethod
    def _csrf_field(auth: AuthState) -> str:
        return f'<input type="hidden" name="csrf" value="{_e(auth.csrf or "")}">'

    @staticmethod
    def _home_for(context: AccessContext) -> str:
        return "/" if context.is_operator else f"/portal/{context.client_id}"

    # -- auth pages -----------------------------------------------------------

    def login_page(self, auth: AuthState, form: dict[str, str],
                   error: str = "") -> Response:
        if auth.signed_in:
            return _redirect(self._home_for(auth.context))
        error_html = f'<p class="error">{_e(error)}</p>' if error else ""
        body = (
            "<div class=\"auth\"><div class=\"card\">"
            "<h1>Sign in</h1>"
            "<p class=\"sub\">LightUp — authorization-first security assessments.</p>"
            f"{error_html}"
            "<form method=\"post\" action=\"/login\">"
            "<label>Email</label><input name=\"email\" type=\"email\" required>"
            "<label>Password</label><input name=\"password\" type=\"password\" required>"
            "<button>Sign in</button></form>"
            "</div></div>"
        )
        return Response(_page("LightUp — Sign in", "login", body, ANONYMOUS))

    def login_submit(self, auth: AuthState, form: dict[str, str]) -> Response:
        try:
            user = self.store.authenticate(form.get("email", ""), form.get("password", ""))
        except AccountLockedError:
            response = self.login_page(
                ANONYMOUS, {}, error="Too many failed sign-ins; try again later.")
            return Response(response.body.decode("utf-8"),
                            status="429 Too Many Requests",
                            extra_headers=[_session_cookie("", clear=True, secure=self.security.production)])
        if user is None:
            response = self.login_page(ANONYMOUS, {}, error="Invalid email or password.")
            return Response(response.body.decode("utf-8"), status="401 Unauthorized",
                            extra_headers=[_session_cookie("", clear=True, secure=self.security.production)])
        if auth.session_token:
            self.store.revoke_session(auth.session_token)
        token, _csrf = self.store.create_session(user.user_id)
        context = self.store.context_for_user(user.user_id)
        return _redirect(self._home_for(context), [_session_cookie(token, secure=self.security.production)])

    def logout(self, auth: AuthState, form: dict[str, str]) -> Response:
        # The dispatcher already verified the session and CSRF token.
        if auth.session_token:
            self.store.revoke_session(auth.session_token)
        return _redirect("/login", [_session_cookie("", clear=True, secure=self.security.production)])

    # -- operator pages -------------------------------------------------------

    def authorization_overview_json(
        self, auth: AuthState, form: dict[str, str]
    ) -> Response:
        import json
        from ..authorization_plan import build_operator_portfolio_review_payload

        # Dispatch requires a real operator session. Domain repeats the
        # operator authorization boundary; no client asset bodies are exported.
        payload = build_operator_portfolio_review_payload(self.store, auth.context)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False) + "\n"
        return Response(
            body,
            content_type="application/json; charset=utf-8",
            extra_headers=[("Content-Disposition",
                            'attachment; filename="lightup-m0-portfolio-review.json"')],
        )

    def authorization_review_worklist_csv(
        self, auth: AuthState, form: dict[str, str],
        kind: str | None = None,
    ) -> Response:
        from ..authorization_plan import (
            build_operator_portfolio_review_payload,
            to_operator_review_worklist_csv,
        )

        # A private review export, not a scope grant or assessment manifest.
        if kind is not None and kind not in _AUTH_REVIEW_ACTIONS:
            raise ValueError("unknown HUMAN worklist export category")
        portfolio = build_operator_portfolio_review_payload(
            self.store, auth.context
        )
        body = to_operator_review_worklist_csv(portfolio, kind=kind)
        filename = (
            f"lightup-m0-human-review-{kind}.csv"
            if kind else "lightup-m0-human-review-worklist.csv"
        )
        return Response(
            body, content_type="text/csv; charset=utf-8",
            extra_headers=[(
                "Content-Disposition",
                f'attachment; filename="{filename}"',
            )],
        )

    def authorization_review_records_csv(
        self, auth: AuthState, form: dict[str, str],
        kind: str | None = None,
    ) -> Response:
        from ..authorization_plan import (
            build_operator_portfolio_review_payload,
            to_operator_review_worklist_csv,
        )

        if kind is not None and kind not in _AUTH_REVIEW_ACTIONS:
            raise ValueError("unknown HUMAN record export category")
        portfolio = build_operator_portfolio_review_payload(
            self.store, auth.context
        )
        # One row per persisted record, never the private target/assets or
        # a grant/consent receipt. Source records remain HOLD/PLAN_ONLY.
        body = to_operator_review_worklist_csv(
            portfolio, kind=kind, records=True,
        )
        filename = (
            f"lightup-m0-human-records-{kind}.csv"
            if kind else "lightup-m0-human-records.csv"
        )
        return Response(
            body, content_type="text/csv; charset=utf-8",
            extra_headers=[(
                "Content-Disposition",
                f'attachment; filename="{filename}"',
            )],
        )

    def authorization_review_worklist(
        self, auth: AuthState, form: dict[str, str],
        kind: str | None = None,
    ) -> Response:
        from ..authorization_plan import build_operator_portfolio_review_payload

        if kind is not None and kind not in _AUTH_REVIEW_ACTIONS:
            raise ValueError("unknown HUMAN review worklist filter")
        portfolio = build_operator_portfolio_review_payload(
            self.store, auth.context
        )
        category_totals = {key: 0 for key in _AUTH_REVIEW_ACTIONS}
        for tenant in portfolio["review_queue"]:
            for action in tenant["actions"]:
                category_totals[action["kind"]] += action["count"]
        items = [
            item for item in portfolio["review_details"]
            if kind is None or item["kind"] == kind
        ]
        order = {code: index for index, code in enumerate(_AUTH_REVIEW_ACTIONS)}
        items.sort(key=lambda item: (
            order[item["kind"]], item["created_at"] or "",
            item["client_id"], item["record_id"],
        ))
        links = [
            (None, "All categories", sum(category_totals.values())),
            *((key, label, category_totals[key])
              for key, label in _AUTH_REVIEW_ACTIONS.items()),
        ]
        filters = " · ".join(
            (
                f'<strong>{_e(label)} ({count})</strong>'
                if key == kind else
                f'<a href="/authorization-reviews'
                f'{"/" + key if key else ""}">{_e(label)} ({count})</a>'
            )
            for key, label, count in links
        )
        cards = []
        for item in items:
            private_plan = (
                f'/clients/{_e(item["client_id"])}/authorization-plan'
            )
            if item["record_type"] == "request":
                target = f'/assessments/requests/{_e(item["record_id"])}/review'
            elif item["record_type"] == "risk_elevation":
                target = f'/assessments/elevations/{_e(item["record_id"])}/review'
            elif item["record_type"] == "engagement":
                target = f'{private_plan}#engagement-{_e(item["record_id"])}'
            else:
                raise ValueError("unknown read-only review pointer")
            cards.append(
                '<section class="card"><div class="row">'
                f'<strong>{_e(item["client_name"])}</strong>'
                '<span class="badge lock">HOLD · human review</span></div>'
                f'<p class="meta">{_e(_AUTH_REVIEW_ACTIONS[item["kind"]])} · '
                f'record {_e(item["record_id"])}</p>'
                f'<a href="{target}">Open exact review record</a>'
                ' · '
                f'<a href="{private_plan}">Private scope context</a></section>'
            )
        csv_path = (
            f"/authorization-reviews/{kind}.csv"
            if kind else "/authorization-reviews.csv"
        )
        records_csv_path = (
            f"/authorization-reviews/{kind}.records.csv"
            if kind else "/authorization-reviews.records.csv"
        )
        body = (
            "<h1>Human authorization review worklist</h1>"
            "<p class=\"sub\">Private operator triage. Counts reflect recorded "
            "review items only; they are not verified consent, a scan permit, "
            "or a reason to bypass revocation-at-use and HUMAN GO.</p>"
            f'<div class="card"><strong>{len(items)} matching original records · '
            'all remain HUMAN review only</strong>'
            f'<p class="meta">{filters}</p>'
            f'<a href="{csv_path}">Download category totals CSV</a>'
            ' · '
            f'<a href="{records_csv_path}">Download exact record worklist CSV</a>'
            ' · <a href="/authorization-overview.json">Full private JSON</a>'
            ' · <a href="/">Back to overview</a></div>'
            + ("".join(cards)
               or '<p class="empty">No recorded items in this category. '
                  'All activation gates remain locked.</p>')
        )
        return Response(_page(
            "LightUp — HUMAN Review", "overview", body, auth
        ))

    def overview(self, auth: AuthState, form: dict[str, str]) -> Response:
        ctx = auth.context
        clients = self.store.list_clients(ctx)
        requests = self.store.list_assessment_requests(ctx)
        open_requests = [r for r in requests
                         if r.status in {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}]
        engagements = self.store.list_engagements(ctx)
        findings = self.store.list_findings(ctx)
        open_retests = [f for f in findings if f.retest_status is not RetestStatus.FIXED]

        from ..authorization_plan import build_operator_portfolio_review_payload

        # The operator HTML and private JSON use one shared fail-closed
        # aggregate representation; no plan is interpreted as execution.
        portfolio = build_operator_portfolio_review_payload(self.store, ctx)
        action_labels = _AUTH_REVIEW_ACTIONS
        review_cards = []
        for item in portfolio["review_queue"]:
            reasons = "".join(
                f'<li>{action["count"]} '
                f'{_e(action_labels[action["kind"]])}</li>'
                for action in item["actions"]
            )
            review_cards.append(
                '<section class="card"><div class="row">'
                f'<strong>{_e(item["client_name"])}</strong>'
                '<span class="badge lock">HOLD · review only</span></div>'
                f'<p class="meta">{item["review_items"]} attention item(s); '
                'not consent or an execution permit.</p>'
                f'<ul>{reasons}</ul>'
                f'<a href="/clients/{_e(item["client_id"])}/authorization-plan">'
                'Open private authorization review</a></section>'
            )
        authorization_rows = []
        for tenant in portfolio["tenants"]:
            client_id = tenant["client_id"]
            authorization_rows.append(
                '<div class="card"><div class="row">'
                f'<a href="/clients/{_e(client_id)}/authorization-plan">'
                f'<strong>{_e(tenant["client_name"])}</strong></a>'
                '<span class="badge lock">HOLD · no execution</span></div>'
                f'<p class="meta">{tenant["requests_awaiting_review"]} request(s) awaiting review · '
                f'{tenant["engagements_hold"]} engagement(s) · '
                f'{tenant["without_current_grant"]} without a current request-bound grant · '
                f'{tenant["expired_grant_engagements"]} expired scope window(s) · '
                f'{tenant["future_dated_grant_engagements"]} not-yet-valid scope window(s) · '
                f'{tenant["pending_risk_decisions"]} pending risk decision(s) · '
                f'{tenant["unrestricted_legacy_scopes"]} unrestricted legacy scope(s)</p>'
                f'<a href="/clients/{_e(client_id)}/authorization-plan">'
                'Review scope and blockers</a></div>'
            )
        body = (
            "<h1>Overview</h1>"
            "<p class=\"sub\">Status first; details live one click deeper.</p>"
            "<div class=\"grid\">"
            f"<div class=\"card\"><div class=\"kpi\">{len(clients)}</div>"
            "<div class=\"kpi-label\">Clients</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{len(open_requests)}</div>"
            "<div class=\"kpi-label\">Requests awaiting review</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{len(engagements)}</div>"
            "<div class=\"kpi-label\">Engagements</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{len(open_retests)}</div>"
            "<div class=\"kpi-label\">Findings awaiting fix/retest</div></div>"
            "</div>"
            "<h2>Authorization control plane</h2>"
            "<p class=\"sub\">Plan-only portfolio review. Every tenant remains HOLD "
            "until independent consent, revocation-at-use, source reviews and HUMAN GO. "
            "<a href=\"/assessments\">Review pending requests</a> · "
            "<a href=\"/authorization-overview.json\">Download private portfolio JSON</a>.</p>"
            "<h3>Human review queue · no automatic activation</h3>"
            '<p class="meta"><a href="/authorization-reviews">'
            'Open filtered worklist</a> · '
            '<a href="/authorization-reviews.csv">Export redacted CSV</a></p>'
            + ("".join(review_cards)
               or "<p class=\"empty\">No immediate recorded review items.</p>")
            + "<h3>All client authorization states</h3>"
            + ("".join(authorization_rows)
               or "<p class=\"empty\">No clients yet.</p>")
            + "<div class=\"card\"><div class=\"row\"><strong>Active testing</strong>"
            "<span class=\"badge lock\">Locked</span></div>"
            "<p class=\"meta\">This build has no real-target execution path. "
            "Unauthorized targets remain passive-discovery only; active capability "
            "adapters arrive behind the activation gate in a later milestone.</p></div>"
        )
        return Response(_page("LightUp — Overview", "overview", body, auth))

    def discovery(self, auth: AuthState, form: dict[str, str]) -> Response:
        prospects = self.store.list_prospects(auth.context)
        csrf = self._csrf_field(auth)
        cards = []
        for p in prospects:
            actions = ""
            if p.status in {ProspectStatus.NEW, ProspectStatus.CONTACTED}:
                next_status = (ProspectStatus.CONTACTED if p.status is ProspectStatus.NEW
                               else ProspectStatus.AUTHORIZATION_REQUESTED)
                label = "Contact" if p.status is ProspectStatus.NEW else "Request authorization"
                actions = (
                    f'<form class="inline" method="post" '
                    f'action="/discovery/prospects/{_e(p.prospect_id)}/status">{csrf}'
                    f'<input type="hidden" name="status" value="{_e(next_status.value)}">'
                    f"<button>{_e(label)}</button></form> "
                    f'<form class="inline" method="post" '
                    f'action="/discovery/prospects/{_e(p.prospect_id)}/status">{csrf}'
                    '<input type="hidden" name="status" value="dismissed">'
                    "<button class=\"secondary\">Dismiss</button></form>"
                )
            cards.append(
                "<div class=\"card\">"
                f"<div class=\"row\"><strong>{_e(p.company)}</strong>"
                "<span class=\"badge lock\">Active testing: Locked</span></div>"
                f"<p>Potential exposure: {_e(p.exposure_summary) or '—'}<br>"
                f"<span class=\"meta\">Confidence {p.confidence:.0%} · "
                f"status {_e(p.status.value)}</span></p>"
                "<details><summary>View signals</summary>"
                "<p class=\"meta\">Signal breakdown arrives with the Discovery "
                "pipeline. Only public, non-intrusive sources are permitted.</p>"
                f"</details>{actions}"
                "</div>"
            )
        body = (
            "<h1>Discovery</h1>"
            "<p class=\"sub\">Passive only. A prospect never becomes an active "
            "target without a recorded authorization grant.</p>"
            + ("".join(cards) or "<p class=\"empty\">No prospects recorded yet.</p>")
            + "<h2>Add prospect (manual, passive signals only)</h2>"
            f"<div class=\"card\"><form method=\"post\" action=\"/discovery/prospects\">{csrf}"
            "<label>Company</label><input name=\"company\" required>"
            "<label>Potential exposure (summary)</label>"
            "<input name=\"exposure_summary\" required>"
            "<label>Confidence (0–100)</label>"
            "<input name=\"confidence\" type=\"number\" min=\"0\" max=\"100\" value=\"50\">"
            "<button>Add prospect</button></form></div>"
        )
        return Response(_page("LightUp — Discovery", "discovery", body, auth))

    def add_prospect(self, auth: AuthState, form: dict[str, str]) -> Response:
        confidence = max(0.0, min(100.0, float(form.get("confidence", "50") or 50))) / 100.0
        self.store.add_prospect(auth.context, form.get("company", ""),
                                form.get("exposure_summary", ""), confidence)
        return _redirect("/discovery")

    def prospect_status(self, auth: AuthState, form: dict[str, str],
                        prospect_id: str) -> Response:
        status = ProspectStatus(form.get("status", ""))
        self.store.set_prospect_status(auth.context, prospect_id, status)
        return _redirect("/discovery")

    def clients(self, auth: AuthState, form: dict[str, str]) -> Response:
        ctx = auth.context
        rows = []
        for c in self.store.list_clients(ctx):
            engagements = self.store.list_engagements(ctx, c.client_id)
            rows.append(
                "<div class=\"card\"><div class=\"row\">"
                f"<a href=\"/clients/{_e(c.client_id)}\"><strong>{_e(c.name)}</strong></a>"
                f"<span class=\"meta\">{len(engagements)} engagement(s)</span></div></div>"
            )
        body = (
            "<h1>Clients</h1>"
            "<p class=\"sub\">Each client has an isolated portal and isolated data.</p>"
            + ("".join(rows) or "<p class=\"empty\">No clients yet.</p>")
            + "<h2>New client</h2><div class=\"card\">"
            f"<form method=\"post\" action=\"/clients\">{self._csrf_field(auth)}"
            "<label>Name</label><input name=\"name\" required>"
            "<button>Create client</button></form></div>"
        )
        return Response(_page("LightUp — Clients", "clients", body, auth))

    def create_client(self, auth: AuthState, form: dict[str, str]) -> Response:
        self.store.create_client(auth.context, form.get("name", ""))
        return _redirect("/clients")

    def client_detail(self, auth: AuthState, form: dict[str, str],
                      client_id: str) -> Response:
        ctx = auth.context
        client = self.store.get_client(ctx, client_id)
        engagements = self.store.list_engagements(ctx, client_id)
        findings = self.store.list_findings(ctx, client_id=client_id)
        approved_requests = tuple(
            request for request in self.store.list_assessment_requests(ctx, client_id)
            if request.status is RequestStatus.APPROVED
            and request.requested_mode is AssessmentMode.AUTHORIZED_ASSESSMENT
            and RiskLevel.PASSIVE <= request.requested_risk <= RiskLevel.ELEVATED
        )
        csrf = self._csrf_field(auth)
        from ..capabilities import CapabilityState, get_capabilities

        planning_capabilities = tuple(
            cap for cap in get_capabilities()
            if cap.state is CapabilityState.PLANNING
        )
        capability_guide = "".join(
            f"<li><code>{_e(cap.capability_id)}</code> — {_e(cap.name)}</li>"
            for cap in planning_capabilities
        )
        engagement_cards = []
        for eng in engagements:
            grant = self.store.get_current_grant(ctx, eng.engagement_id)
            grant_badge = ("<span class=\"badge ok\">Current recorded grant · execution OFF</span>" if grant
                           else "<span class=\"badge warn\">No current authorization</span>")
            grant_detail = ""
            if grant:
                grant_detail = (
                    "<details><summary>Authorization details</summary><p class=\"meta\">"
                    f"Reference {_e(grant.reference)} · approved by {_e(grant.approved_by)}"
                    f"<br>Assets: {_e(', '.join(grant.scope.assets))}"
                    f"<br>Capabilities: {_e(', '.join(grant.scope.allowed_capabilities) or 'ALL — unrestricted legacy scope; review required')}"
                    f"<br>Max risk: {_risk(grant.scope.max_risk)}"
                    f"<br>Valid {_e(grant.valid_from.date())} – {_e(grant.valid_until.date())}"
                    "</p></details>"
                )
            elif not approved_requests:
                grant_detail = (
                    "<p class=\"meta\">An approved client request is required "
                    "before any scope grant can be recorded. Have the client "
                    "submit a request, then review it in Assessments. "
                    "Execution stays OFF.</p>"
                )
            else:
                grant_forms = []
                for request in approved_requests:
                    risk_options = "".join(
                        f'<option value="{level.value}">{level.value} — {_e(label)}</option>'
                        for level, label in (
                            (RiskLevel.PASSIVE, "Passive"),
                            (RiskLevel.LOW_IMPACT, "Low impact"),
                            (RiskLevel.STANDARD, "Standard"),
                            (RiskLevel.ELEVATED, "Elevated"),
                        )
                        if level <= request.requested_risk
                    )
                    requested_assets = ", ".join(request.requested_assets)
                    grant_forms.append(
                        '<section class="grant-request">'
                        '<p><strong>Approved client request</strong> '
                        f'<code>{_e(request.request_id)}</code> · '
                        f'Client risk ceiling: {_risk(request.requested_risk)}</p>'
                        f'<p class="meta">Reviewed requested assets: {_e(requested_assets)}</p>'
                        f'<form method="post" action="/engagements/{_e(eng.engagement_id)}/grants">'
                        f'{csrf}'
                        f'<input type="hidden" name="approved_request_id" value="{_e(request.request_id)}">'
                        '<label>Approved by (client signatory; verify separately)</label>'
                        '<input name="approved_by" required>'
                        '<label>Authorization reference</label>'
                        '<input name="reference" required placeholder="AUTH-2026-...">'
                        '<label>Authorized assets (explicit subset, comma-separated)</label>'
                        f'<input name="assets" required placeholder="{_e(requested_assets[:96])}">'
                        '<label>Excluded assets (comma-separated, optional)</label>'
                        '<input name="excluded_assets">'
                        '<label>Allowed planning capability IDs (comma-separated; required)</label>'
                        '<input name="capabilities" required placeholder="web-baseline">'
                        '<details><summary>Show available planning capability IDs</summary>'
                        f'<ul>{capability_guide}</ul></details>'
                        '<label>Maximum risk level (within this request)</label>'
                        '<select name="max_risk" required>'
                        '<option value="" selected disabled>Explicitly choose an allowed ceiling</option>'
                        f'{risk_options}</select>'
                        '<label>Valid for (days)</label>'
                        '<input name="valid_days" type="number" min="1" max="365" required>'
                        '<button>Record grant for this request</button>'
                        '<p class="meta">Grant recording binds scope to this exact reviewed request, '
                        'but does not prove independent client consent or permit execution. '
                        'Destructive simulation (level 5) is lab-only, never available here.</p>'
                        '</form></section>'
                    )
                grant_detail = (
                    '<details><summary>Record authorization grant</summary>'
                    '<p class="meta">Each form is bound to one approved client request. '
                    'Select assets, planning capabilities, risk and validity deliberately.</p>'
                    + "".join(grant_forms)
                    + '</details>'
                )
            engagement_cards.append(
                "<div class=\"card\"><div class=\"row\">"
                f"<strong>{_e(eng.name)}</strong>{grant_badge}</div>"
                f"<p class=\"meta\">Status: {_e(eng.status.value)}</p>{grant_detail}</div>"
            )
        new_engagement = (
            "<div class=\"card\">"
            f"<form method=\"post\" action=\"/clients/{_e(client.client_id)}/engagements\">"
            f"{csrf}"
            "<label>Engagement name</label><input name=\"name\" required>"
            "<button>Create engagement</button></form></div>"
        )
        body = (
            f"<h1>{_e(client.name)}</h1>"
            f"<p class=\"sub\">Portal: <a href=\"/portal/{_e(client.client_id)}\">"
            "open client portal</a> · "
            f"<a href=\"/clients/{_e(client.client_id)}/authorization-plan\">"
            "Plan-only authorization review</a></p>"
            "<h2>Engagements</h2>"
            + ("".join(engagement_cards) or "<p class=\"empty\">No engagements yet.</p>")
            + f"<h2>New engagement</h2>{new_engagement}"
            + "<h2>Coverage</h2>"
            + ("".join(self._coverage_card(ctx, e.engagement_id, e.name)
                       for e in engagements)
               or "<p class=\"empty\">No engagements yet.</p>")
            + f"<h2>Findings</h2>{self._finding_cards(findings)}"
        )
        return Response(_page(f"LightUp — {client.name}", "clients", body, auth))

    def authorization_plan(self, auth: AuthState, form: dict[str, str],
                           client_id: str) -> Response:
        return self._authorization_plan_page(auth, client_id, portal=False)

    def portal_authorization_plan(self, auth: AuthState, form: dict[str, str],
                                  client_id: str) -> Response:
        return self._authorization_plan_page(auth, client_id, portal=True)

    def authorization_plan_json(self, auth: AuthState, form: dict[str, str],
                                client_id: str) -> Response:
        return self._authorization_plan_json(auth, client_id, portal=False)

    def portal_authorization_plan_json(self, auth: AuthState, form: dict[str, str],
                                       client_id: str) -> Response:
        return self._authorization_plan_json(auth, client_id, portal=True)

    def _authorization_plan_json(self, auth: AuthState, client_id: str,
                                 *, portal: bool) -> Response:
        import json
        from ..authorization_plan import build_client_authorization_plan, to_review_payload

        # Same verified session and domain tenant isolation as the HTML view.
        # No grant writes, capability dispatch, consent or active actions.
        viewer = self._portal_context(auth, client_id) if portal else auth.context
        plan = build_client_authorization_plan(self.store, viewer, client_id)
        payload = json.dumps(to_review_payload(plan), ensure_ascii=False,
                             sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        return Response(
            payload,
            content_type="application/json; charset=utf-8",
            extra_headers=[("Content-Disposition",
                            'attachment; filename="lightup-plan-only-review.json"')],
        )

    def _authorization_plan_page(self, auth: AuthState, client_id: str,
                                 *, portal: bool) -> Response:
        from ..authorization_plan import build_client_authorization_plan

        # No grant, consent, permit or target side effects; tenant scope is
        # still checked by every original domain read.
        viewer = self._portal_context(auth, client_id) if portal else auth.context
        plan = build_client_authorization_plan(self.store, viewer, client_id)
        request_cards = []
        for request in plan.request_reviews:
            if request.status == RequestStatus.APPROVED.value:
                next_step = ("Reviewed request only. Compare its exact assets and "
                             "risk with any separately recorded scope grant.")
            elif request.status == RequestStatus.REJECTED.value:
                next_step = "Rejected. This request cannot be used as a grant."
            else:
                next_step = ("Waiting for independent operator review. No grant "
                             "or execution permission is implied.")
            request_cards.append(
                '<section class="card"><div class="row">'
                f'<strong>Request {_e(request.request_id)}</strong>'
                f'<span class="badge">{_e(request.status)}</span></div>'
                f'<p class="meta">Requested assets: {_e(", ".join(request.requested_assets))}<br>'
                f'Mode: {_e(request.requested_mode.replace("_", " "))} · '
                f'Risk: {_risk(request.requested_risk)}<br>'
                f'Submitted: {_e(request.submitted_at)}'
                + (f' · Reviewed: {_e(request.reviewed_at)}' if request.reviewed_at else "")
                + f'</p><p class="meta">{_e(next_step)}</p></section>'
            )
        cards = []
        for entry in plan.engagements:
            capability_description = (
                "ALL capabilities · unrestricted legacy grant requires review"
                if entry.unrestricted_capabilities_recorded
                else ", ".join(entry.recorded_capabilities) or "None recorded"
            )
            historical_window = (
                (f'<br>Last eligible recorded grant expired: '
                 f'{_e(entry.last_eligible_grant_expired_at)}'
                 if entry.last_eligible_grant_expired_at else '')
                + (f'<br>Next eligible recorded grant begins: '
                   f'{_e(entry.next_eligible_grant_valid_from)}'
                   if entry.next_eligible_grant_valid_from else '')
            )
            scope = (
                "<details><summary>Recorded scope (not execution permission)</summary>"
                f"<p class=\"meta\">Assets: {_e(', '.join(entry.recorded_scope))}<br>"
                f"Excluded: {_e(', '.join(entry.excluded_scope) or 'None recorded')}<br>"
                f"Recorded risk ceiling: {_risk(entry.max_risk) if entry.max_risk is not None else '—'}<br>"
                f"Recorded capability scope: {_e(capability_description)}<br>"
                f"Valid from: {_e(entry.grant_valid_from or '—')}<br>"
                f"Valid until: {_e(entry.grant_valid_until or '—')}"
                "</p></details>"
                if entry.recorded_scope else (
                    '<p class="meta">No current request-bound scope grant.<br>'
                    f'Recorded window state: {_e(entry.scope_record_state.replace("_", " ").lower())}'
                    f'{historical_window}</p>'
                )
            )
            risk_reviews = []
            for review in entry.risk_elevation_reviews:
                reviewed = (
                    f' · Decision recorded: {_e(review.reviewed_at)}'
                    if review.reviewed_at else ''
                )
                risk_reviews.append(
                    '<li>'
                    f'<code>{_e(review.approval_id)}</code> · '
                    f'{_e(review.status)} · requested ceiling {_risk(review.requested_risk)}'
                    f' · Requested: {_e(review.requested_at)}{reviewed}'
                    '</li>'
                )
            risk_history = (
                f'<details><summary>Risk-elevation review history '
                f'({len(risk_reviews)} recorded; no execution authority)</summary>'
                f'<ul>{"".join(risk_reviews)}</ul>'
                '<p class="meta">Risk decisions never extend a recorded request-bound '
                'scope grant or verify client consent.</p></details>'
                if risk_reviews else ''
            )
            blockers = "".join(f"<li>{_e(reason)}</li>" for reason in entry.blockers)
            cards.append(
                f'<section class="card" id="engagement-{_e(entry.engagement_id)}">'
                '<div class="row">'
                f"<strong>{_e(entry.name)}</strong>"
                "<span class=\"badge lock\">HOLD · no execution</span></div>"
                f"<p class=\"meta\">Engagement: {_e(entry.status)} · "
                f"Pending risk decisions: {entry.pending_elevations} · "
                f"Current scope: {_e(entry.scope_record_state.replace('_', ' ').lower())}</p>"
                f"{scope}{risk_history}<details open><summary>What is still required</summary>"
                f"<ul>{blockers}</ul></details></section>"
            )
        body = (
            f"<h1>{_e(plan.client_name)} — authorization plan</h1>"
            "<p class=\"sub\">Read-only M0 workspace. Existing records are shown "
            "for HUMAN review. There is no scan, apply or activation button; "
            "even a current recorded grant never enables execution here.</p>"
            "<div class=\"card\"><span class=\"badge lock\">PLAN ONLY · ACTIVATION OFF</span>"
            f"<p class=\"meta\">Requests: {plan.submitted_requests} awaiting review · "
            f"{plan.approved_requests} approved · {plan.rejected_requests} rejected. "
            "A client-level request is not automatically linked to an engagement.</p>"
            "<p class=\"meta\">Before any future release, independently verify real "
            "client and operator consent, request/scope provenance, action-time "
            "revocation, source/security reviews and explicit HUMAN GO.</p></div>"
            "<h2>Client requests · review history</h2>"
            + ("".join(request_cards)
               or "<p class=\"empty\">No requests yet. A client must submit one first.</p>")
            + "<p class=\"meta\">Requests are client-level records, never consent "
              "or engagement execution authority.</p>"
            + "<h2>Engagement decisions</h2>"
            + ("".join(cards) or "<p class=\"empty\">No engagements yet.</p>")
            + (f"<p><a href=\"/portal/{_e(plan.client_id)}/authorization-plan.json\">"
               "Download private plan-only review (JSON)</a></p>"
               if portal else
               f"<p><a href=\"/clients/{_e(plan.client_id)}/authorization-plan.json\">"
               "Download private plan-only review (JSON)</a></p>")
            + (f"<p><a href=\"/portal/{_e(plan.client_id)}\">Back to portal</a></p>"
               if portal else f"<p><a href=\"/clients/{_e(plan.client_id)}\">Back to client</a></p>")
        )
        return Response(_page("LightUp — Authorization plan",
                              "scope" if portal else "clients", body, auth,
                              portal_client=client_id if portal else None))

    def create_engagement(self, auth: AuthState, form: dict[str, str],
                          client_id: str) -> Response:
        self.store.create_engagement(auth.context, client_id, form.get("name", ""))
        return _redirect(f"/clients/{client_id}")

    def record_grant(self, auth: AuthState, form: dict[str, str],
                     engagement_id: str) -> Response:
        from datetime import datetime, timedelta, timezone

        from ..engagements import ScopeDefinition
        from ..capabilities import CapabilityState, get_capabilities

        def _csv(name: str) -> tuple[str, ...]:
            return tuple(part.strip() for part in form.get(name, "").split(",")
                         if part.strip())

        raw_max_risk = form.get("max_risk")
        if raw_max_risk is None or not raw_max_risk.strip():
            raise ValueError("maximum risk is required")
        if raw_max_risk == str(int(RiskLevel.DESTRUCTIVE_LAB_ONLY)):
            raise ValueError("destructive simulation cannot be granted for client assets")
        if raw_max_risk not in {"1", "2", "3", "4"}:
            raise ValueError("maximum risk must be one of 1, 2, 3, or 4")
        max_risk = RiskLevel(int(raw_max_risk))

        raw_valid_days = form.get("valid_days")
        if raw_valid_days is None or not raw_valid_days.strip():
            raise ValueError("grant validity is required")
        if not raw_valid_days.isascii() or not raw_valid_days.isdigit():
            raise ValueError("grant validity must be a whole number of days")
        valid_days = int(raw_valid_days)
        if not 1 <= valid_days <= 365:
            raise ValueError("grant validity must be between 1 and 365 days")
        capabilities = _csv("capabilities")
        permitted = {
            cap.capability_id for cap in get_capabilities()
            if cap.state is CapabilityState.PLANNING
        }
        if (not capabilities or len(set(capabilities)) != len(capabilities)
                or any(cap not in permitted for cap in capabilities)):
            raise ValueError("grant must explicitly name unique known planning capabilities")
        approved_request_id = form.get("approved_request_id")
        if type(approved_request_id) is not str or not approved_request_id.strip():
            raise ValueError("one explicitly approved client request is required")
        now = datetime.now(timezone.utc)
        scope = ScopeDefinition(
            assets=_csv("assets"),
            max_risk=max_risk,
            allowed_capabilities=capabilities,
            excluded_assets=_csv("excluded_assets"),
        )
        engagement = self.store.get_engagement(auth.context, engagement_id)
        self.store.record_authorization_grant(
            auth.context, engagement_id,
            approved_by=form.get("approved_by", ""),
            reference=form.get("reference", ""),
            scope=scope, valid_from=now,
            valid_until=now + timedelta(days=valid_days),
            approved_request_id=approved_request_id,
        )
        return _redirect(f"/clients/{engagement.client_id}")

    def assessments(self, auth: AuthState, form: dict[str, str]) -> Response:
        """Operator-only human decision inbox; no request grants scan authority."""
        ctx = auth.context
        requests = sorted(
            self.store.list_assessment_requests(ctx),
            key=lambda item: (item.created_at, item.request_id),
            reverse=True,
        )
        approvals = [
            item for item in self.store.list_risk_approvals(ctx)
            if item.status.value == "pending"
        ]
        pending_requests = []
        decided_requests = []
        for request in requests:
            client = self.store.get_client(ctx, request.client_id)
            pending = request.status in {
                RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
            }
            if request.status not in {
                RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
                RequestStatus.APPROVED, RequestStatus.REJECTED,
            }:
                raise ValueError("unknown persisted HUMAN review state")
            action = (
                "Open deliberate human decision" if pending
                else "View recorded human decision"
            )
            card = (
                '<section class="card"><div class="row">'
                f'<strong>{_e(client.name)}</strong>'
                f'<span class="badge">{_e(request.status.value)}</span></div>'
                f'<p class="meta">Submitted {_e(request.created_at)}'
                + (f' · Decided {_e(request.decided_at)}'
                   if request.decided_at else '')
                + f' · Requested risk: {_risk(request.requested_risk)}'
                f' · Mode {_e(request.requested_mode.value)}</p>'
                '<details><summary>Requested systems and notes</summary>'
                f'<p class="meta">Systems: {_e(", ".join(request.requested_assets))}</p>'
                f'<p class="meta">Notes: {_e(request.notes) or "—"}</p></details>'
                f'<a href="/assessments/requests/{_e(request.request_id)}/review">'
                f'{action}</a></section>'
            )
            (pending_requests if pending else decided_requests).append(card)

        elevation_cards = []
        for approval in approvals:
            elevation_cards.append(
                '<section class="card"><div class="row">'
                f'<strong>Risk elevation to {_risk(approval.requested_risk)}</strong>'
                '<span class="badge warn">Human decision required</span></div>'
                f'<p class="meta">Engagement {_e(approval.engagement_id)} · '
                f'Requested by {_e(approval.requested_by)}</p>'
                '<details><summary>Justification</summary>'
                f'<p class="meta">{_e(approval.justification)}</p></details>'
                f'<a href="/assessments/elevations/{_e(approval.approval_id)}/review">'
                'Open deliberate risk review</a></section>'
            )
        body = (
            '<h1>Human assessment decisions</h1>'
            '<p class="sub">Review original client requests and risk elevations. '
            'Every decision remains separate from scope grants, current consent, '
            'revocation-at-use and HUMAN GO. Active testing is locked.</p>'
            '<div class="grid">'
            f'<section class="card"><div class="kpi">{len(pending_requests)}</div>'
            '<div class="kpi-label">Client requests awaiting review</div></section>'
            f'<section class="card"><div class="kpi">{len(elevation_cards)}</div>'
            '<div class="kpi-label">Risk elevations awaiting review</div></section>'
            f'<section class="card"><div class="kpi">{len(decided_requests)}</div>'
            '<div class="kpi-label">Recorded request decisions</div></section>'
            '</div>'
            f'<h2>Review client requests ({len(pending_requests)})</h2>'
            + ("".join(pending_requests) or
               '<p class="empty">No client requests awaiting a decision.</p>')
            + f'<h2>Review elevated-risk requests ({len(elevation_cards)})</h2>'
            + ("".join(elevation_cards) or
               '<p class="empty">No elevated-risk decisions awaiting review.</p>')
            + f'<details><summary>Decided request history ({len(decided_requests)})</summary>'
            + ("".join(decided_requests) or
               '<p class="empty">No previous human request decisions.</p>')
            + '</details>'
            + '<p class="meta">A human review is never independent client consent '
            'or permission to contact a target. '
            '<a href="/authorization-reviews">Open complete scope review worklist</a>.</p>'
        )
        return Response(_page("LightUp — Human decisions", "assessments", body, auth))

    def review_request_page(
        self, auth: AuthState, form: dict[str, str], request_id: str,
    ) -> Response:
        ctx = auth.context
        request = self.store.get_assessment_request(ctx, request_id)
        client = self.store.get_client(ctx, request.client_id)
        pending = request.status in {
            RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
        }
        controls = ""
        if pending:
            choices = []
            for decision, label in (
                ("approve", "Approve this request for scope review"),
                ("reject", "Reject this request"),
            ):
                choices.append(
                    '<form method="post" class="card" '
                    f'action="/assessments/requests/{_e(request_id)}/decision">'
                    f'{self._csrf_field(auth)}'
                    f'<input type="hidden" name="decision" value="{decision}">'
                    '<label class="review-ack">'
                    '<input type="checkbox" name="reviewed" value="yes" required>'
                    '<span>I read the client-origin request, assets and risk. '
                    'This decision is not independent client consent and cannot '
                    'activate testing.</span></label>'
                    f'<button>{_e(label)}</button></form>'
                )
            controls = "".join(choices)
        body = (
            "<h1>Review client assessment request</h1>"
            '<p class="sub">A human decision on the request only. '
            'No scope grant, consent receipt or execution permission is created here.</p>'
            '<section class="card">'
            f'<p><strong>Client:</strong> {_e(client.name)} · '
            f'<strong>Status:</strong> {_e(request.status.value)}</p>'
            f'<p><strong>Requested systems:</strong> '
            f'{_e(", ".join(request.requested_assets))}</p>'
            f'<p><strong>Risk:</strong> {_risk(request.requested_risk)} · '
            f'<strong>Mode:</strong> {_e(request.requested_mode.value)}</p>'
            f'<p><strong>Client request origin:</strong> {_e(request.requested_by)} · '
            f'<strong>Submitted:</strong> {_e(request.submitted_at)}</p>'
            f'<p><strong>Notes:</strong> {_e(request.notes) or "None"}</p>'
            '<p class="meta">Reviewing this request never verifies system '
            'ownership, action-time revocation or HUMAN GO.</p></section>'
            + (controls or '<p class="empty">Decision already recorded; '
               'no further decision is available here.</p>')
            + '<p><a href="/assessments">Back to operator reviews</a></p>'
        )
        return Response(_page(
            "LightUp — Review request", "assessments", body, auth,
        ))

    def review_elevation_page(
        self, auth: AuthState, form: dict[str, str], approval_id: str,
    ) -> Response:
        ctx = auth.context
        decision = next(
            (item for item in self.store.list_risk_approvals(ctx)
             if item.approval_id == approval_id), None,
        )
        if decision is None:
            raise KeyError("risk review not found")
        engagement = self.store.get_engagement(ctx, decision.engagement_id)
        client = self.store.get_client(ctx, engagement.client_id)
        controls = ""
        if decision.status.value == "pending":
            choices = []
            for choice, label in (
                ("approve", "Record risk-elevation approval"),
                ("deny", "Deny risk elevation"),
            ):
                choices.append(
                    '<form method="post" class="card" '
                    f'action="/assessments/elevations/{_e(approval_id)}/decision">'
                    f'{self._csrf_field(auth)}'
                    f'<input type="hidden" name="decision" value="{choice}">'
                    '<label class="review-ack">'
                    '<input type="checkbox" name="reviewed" value="yes" required>'
                    '<span>I read the requested elevated risk and justification. '
                    'A decision here never widens the separate recorded scope '
                    'grant or authorizes execution.</span></label>'
                    f'<button>{_e(label)}</button></form>'
                )
            controls = "".join(choices)
        body = (
            "<h1>Review proposed risk elevation</h1>"
            '<p class="sub">Read the justification before choosing. '
            'Even an approved elevation does not activate capabilities.</p>'
            '<section class="card">'
            f'<p><strong>Client:</strong> {_e(client.name)} · '
            f'<strong>Engagement:</strong> {_e(engagement.name)}</p>'
            f'<p><strong>Status:</strong> {_e(decision.status.value)} · '
            f'<strong>Requested risk:</strong> {_risk(decision.requested_risk)}</p>'
            f'<p><strong>Requested by:</strong> {_e(decision.requested_by)}</p>'
            f'<p><strong>Justification:</strong> {_e(decision.justification)}</p>'
            '<p class="meta">The original reviewed client request, scope grant, '
            'consent and revocation-at-use remain independent prerequisites.</p>'
            '</section>'
            + (controls or '<p class="empty">No pending decision remains.</p>')
            + '<p><a href="/assessments">Back to operator reviews</a></p>'
        )
        return Response(_page(
            "LightUp — Risk review", "assessments", body, auth,
        ))

    def decide_request(self, auth: AuthState, form: dict[str, str],
                       request_id: str) -> Response:
        decision = form.get("decision")
        if form.get("reviewed") != "yes":
            raise ValueError("operator must explicitly confirm request review")
        if decision not in {"approve", "reject"}:
            raise ValueError("assessment decision must be exactly approve or reject")
        self.store.review_assessment_request(
            auth.context, request_id, decision == "approve"
        )
        return _redirect(f"/assessments/requests/{request_id}/review")

    def decide_elevation(self, auth: AuthState, form: dict[str, str],
                         approval_id: str) -> Response:
        decision = form.get("decision")
        if form.get("reviewed") != "yes":
            raise ValueError("operator must explicitly confirm risk review")
        if decision not in {"approve", "deny"}:
            raise ValueError("risk-elevation decision must be exactly approve or deny")
        self.store.decide_risk_elevation(
            auth.context, approval_id, decision == "approve"
        )
        return _redirect(f"/assessments/elevations/{approval_id}/review")

    # -- client portal --------------------------------------------------------

    def _portal_context(self, auth: AuthState, client_id: str) -> AccessContext:
        """The acting context for portal pages.

        Operators browse a portal with an explicit client-scoped view context;
        clients act as themselves. Dispatch already rejected mismatched clients.
        """
        if auth.is_operator:
            return AccessContext(user_id=auth.context.user_id, role=Role.CLIENT_ADMIN,
                                 client_id=client_id)
        return auth.context

    def portal(self, auth: AuthState, form: dict[str, str], client_id: str) -> Response:
        ctx = self._portal_context(auth, client_id)
        client = self.store.get_client(ctx, client_id)
        findings = self.store.list_findings(ctx)
        # Keep the overview minimal: raw scope assets belong only to the
        # authenticated per-request receipt, not a default landing screen.
        requests = self.store.list_assessment_requests(ctx, client_id)
        if any(item.client_id != client_id for item in requests):
            raise TenantIsolationError("cross-tenant portal overview denied")
        ordered_requests = sorted(
            requests, key=lambda item: (item.created_at, item.request_id),
            reverse=True,
        )
        fixed = sum(1 for f in findings if f.retest_status is RetestStatus.FIXED)
        request_rows = "".join(
            '<section class="card"><div class="row">'
            f'<strong>Request {_e(r.request_id[:8])}</strong>'
            f'<span class="badge">{_e(r.status.value)}</span></div>'
            f'<p class="meta">Submitted {_e(r.created_at)} · '
            f'Requested risk: {_risk(r.requested_risk)}</p>'
            f'<a href="/portal/{_e(client_id)}/requests/{_e(r.request_id)}">'
            'View private request details and safety steps</a></section>'
            for r in ordered_requests[:3]
        ) or '<p class="empty">No assessment requests yet.</p>'
        if auth.is_operator:
            request_section = (
                "<h2>Assessment request submissions</h2>"
                "<p class=\"sub\">Read-only operator view. Only the client's "
                "own signed-in users may submit an assessment request. "
                "Review existing requests from the operator Assessments page.</p>"
            )
        else:
            request_section = (
                '<h2 id="new-request">Ask for a security assessment</h2>'
                "<div class=\"card\">"
                "<p class=\"meta\">Step 1 of 2: describe what you want reviewed. "
                "Nothing will be tested or activated by this request.</p>"
                f"<form method=\"post\" action=\"/portal/{_e(client_id)}/requests/preview\">"
                f"{self._csrf_field(auth)}"
                '<label for="request-assets">Systems you manage (separate with commas)</label>'
                '<input id="request-assets" name="assets" autocomplete="off" required '
                'aria-describedby="request-assets-help">'
                '<p id="request-assets-help" class="meta">Only name systems you own or '
                'are explicitly allowed to request a review for. This entry does not '
                'verify ownership.</p>'
                '<label for="request-risk">Requested testing risk</label>'
                '<select id="request-risk" name="risk" required '
                'aria-describedby="request-risk-help">'
                '<option value="" selected>Choose a level…</option>'
                '<option value="1">1 — Passive: observation only</option>'
                '<option value="2">2 — Low impact: needs separate authorization</option>'
                '<option value="3">3 — Standard: needs separate authorization</option>'
                '<option value="4">4 — Elevated: needs additional risk review</option>'
                '</select>'
                '<p id="request-risk-help" class="meta">Choosing a level never gives '
                'LightUp permission to run it.</p>'
                '<label for="request-notes">Context for the reviewer (optional)</label>'
                '<textarea id="request-notes" name="notes" rows="3"></textarea>'
                '<button>Review before sending</button>'
                '<p class="meta">An operator must separately review the request. '
                'Testing stays locked until independent consent, scope validation, '
                'action-time revocation checks and HUMAN GO.</p></form></div>'
            )
        body = (
            f"<h1>{_e(client.name)}</h1>"
            "<p class=\"sub\">Your security posture, in plain terms.</p>"
            "<div class=\"grid\">"
            f"<div class=\"card\"><div class=\"kpi\">{len(findings)}</div>"
            "<div class=\"kpi-label\">Findings</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{fixed}</div>"
            "<div class=\"kpi-label\">Confirmed fixed</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{len(requests)}</div>"
            "<div class=\"kpi-label\">Assessment requests</div></div>"
            "</div>"
            f"<h2>Findings</h2>{self._finding_cards(findings, portal=True)}"
            "<h2>What has been assessed</h2>"
            + ("".join(self._coverage_card(ctx, e.engagement_id, e.name)
                       for e in self.store.list_engagements(ctx))
               or "<p class=\"empty\">No engagements yet.</p>")
            + f'<h2>Recent assessment requests</h2><p><a href="/portal/{_e(client_id)}/requests">'
              f'Open all {len(requests)} requests in the private inbox</a></p>'
            + request_rows
            + f"<p><a href=\"/portal/{_e(client_id)}/authorization-plan\">"
              "Review authorization plan (read-only)</a></p>"
            + request_section
        )
        return Response(_page(f"LightUp — {client.name}", "portal", body, auth,
                              portal_client=client_id))

    def portal_requests(
        self, auth: AuthState, form: dict[str, str], client_id: str,
    ) -> Response:
        """Tenant-private HUMAN review inbox; there are no state-changing links."""
        viewer = self._portal_context(auth, client_id)
        client = self.store.get_client(viewer, client_id)
        requests = self.store.list_assessment_requests(viewer, client_id)
        if any(item.client_id != client_id for item in requests):
            raise TenantIsolationError("cross-tenant request list denied")
        ordered = sorted(
            requests, key=lambda item: (item.created_at, item.request_id),
            reverse=True,
        )
        awaiting = [
            item for item in ordered
            if item.status in {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}
        ]
        decided = [
            item for item in ordered
            if item.status in {RequestStatus.APPROVED, RequestStatus.REJECTED}
        ]

        def render_row(request) -> str:
            next_step = {
                RequestStatus.SUBMITTED: "Waiting for independent operator review.",
                RequestStatus.UNDER_REVIEW: "Operator review in progress.",
                RequestStatus.APPROVED: "Request approved only. Check separate scope and consent.",
                RequestStatus.REJECTED: "Request rejected. No scope authority created.",
            }[request.status]
            return (
                '<section class="card"><div class="row">'
                f'<strong>Request {_e(request.request_id)}</strong>'
                f'<span class="badge">{_e(request.status.value)}</span></div>'
                f'<p class="meta">Submitted: {_e(request.created_at)}'
                + (f' · Decided: {_e(request.decided_at)}'
                   if request.decided_at else '')
                + f' · Requested risk: {_risk(request.requested_risk)}</p>'
                f'<p class="meta">{_e(next_step)}</p>'
                f'<a href="/portal/{_e(client_id)}/requests/{_e(request.request_id)}">'
                'Open private status and safety steps</a>'
                '</section>'
            )

        submit_link = (
            f'<a href="/portal/{_e(client_id)}#new-request">Prepare a new request</a>'
            if not auth.is_operator else
            'Operator view is read-only; only an original client session may submit.'
        )
        body = (
            '<h1>Assessment requests</h1>'
            f'<p class="sub">{_e(client.name)} · Human review only. '
            'Request approval never activates a scan.</p>'
            f'<section class="card"><strong>{len(awaiting)} awaiting review · '
            f'{len(decided)} decided</strong>'
            '<p class="meta">All records remain PLAN ONLY until separate '
            'scope, consent, action-time revocation and HUMAN GO.</p>'
            f'<p>{submit_link} · '
            f'<a href="/portal/{_e(client_id)}">Back to overview</a> · '
            f'<a href="/portal/{_e(client_id)}/requests.json">'
            'Download private status index (JSON)</a></p></section>'
            f'<h2>Waiting for review ({len(awaiting)})</h2>'
            + ("".join(render_row(item) for item in awaiting)
               or '<p class="empty">No requests currently waiting for a decision.</p>')
            + f'<h2>Reviewed requests ({len(decided)})</h2>'
            + ("".join(render_row(item) for item in decided)
               or '<p class="empty">No operator decisions recorded yet.</p>')
        )
        return Response(_page(
            "LightUp — Request inbox", "requests", body, auth,
            portal_client=client_id,
        ))

    def portal_requests_json(
        self, auth: AuthState, form: dict[str, str], client_id: str,
    ) -> Response:
        """Tenant-private original request status index, never scan authority.

        Raw asset names, notes, request origins and grants are omitted from the
        machine-readable overview. Details require an access-checked receipt.
        """
        import json
        from datetime import datetime, timezone

        viewer = self._portal_context(auth, client_id)
        self.store.get_client(viewer, client_id)
        requests = self.store.list_assessment_requests(viewer, client_id)
        if any(item.client_id != client_id for item in requests):
            raise TenantIsolationError("cross-tenant request status index denied")
        ordered = sorted(
            requests, key=lambda item: (item.created_at, item.request_id),
            reverse=True,
        )
        awaiting = {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}
        decided = {RequestStatus.APPROVED, RequestStatus.REJECTED}
        if any(item.status not in awaiting | decided for item in ordered):
            raise ValueError("unrecognized persisted request state")

        payload = {
            "format": "lightup-m0-request-index-v1",
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
            "state": "PLAN_ONLY",
            "counts": {
                "total": len(ordered),
                "awaiting_human_review": sum(
                    item.status in awaiting for item in ordered
                ),
                "decided": sum(item.status in decided for item in ordered),
            },
            "requests": [
                {
                    "request_id": item.request_id,
                    "status": item.status.value,
                    "submitted_at": item.created_at,
                    "reviewed_at": item.decided_at,
                    "requested_risk": int(item.requested_risk),
                    "status_receipt_url": (
                        f"/portal/{client_id}/requests/{item.request_id}.json"
                    ),
                }
                for item in ordered
            ],
            "authority": {
                "engagement_grant_inferred": False,
                "client_consent_verified": False,
                "revocation_at_use_verified": False,
                "human_go_verified": False,
                "execution_allowed": False,
            },
            "disclaimer": (
                "Unsigned tenant-private request index, not verified ownership, "
                "scope authorization, consent or scan permission."
            ),
        }
        body = json.dumps(
            payload, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ) + "\n"
        return Response(
            body, content_type="application/json; charset=utf-8",
            extra_headers=[(
                "Content-Disposition",
                'attachment; filename="lightup-request-index.json"',
            )],
        )

    def portal_request_receipt_json(
        self, auth: AuthState, form: dict[str, str],
        client_id: str, request_id: str,
    ) -> Response:
        """Private, per-request status receipt; never a consent/scan token."""
        import json
        from datetime import datetime, timezone

        viewer = self._portal_context(auth, client_id)
        request = self.store.get_assessment_request(viewer, request_id)
        if request.client_id != client_id:
            raise TenantIsolationError("cross-tenant request receipt denied")
        awaiting = request.status in {
            RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
        }
        payload = {
            "format": "lightup-m0-request-status-v1",
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "client_id": request.client_id,
            "request_id": request.request_id,
            "status": request.status.value,
            "requested_assets": list(request.requested_assets),
            "requested_mode": request.requested_mode.value,
            "requested_risk": int(request.requested_risk),
            "submitted_at": request.created_at,
            "reviewed_at": request.decided_at,
            "progress": _request_progress(request.status),
            "next_step": (
                "AWAIT_INDEPENDENT_OPERATOR_REVIEW"
                if awaiting else
                "REVIEW_SEPARATE_SCOPE_AND_CONSENT_GATES"
                if request.status is RequestStatus.APPROVED else
                "REQUEST_REJECTED_NO_SCOPE_AUTHORITY"
            ),
            "state": "PLAN_ONLY",
            "authority": {
                "engagement_grant_inferred": False,
                "client_consent_verified": False,
                "revocation_at_use_verified": False,
                "human_go_verified": False,
                "execution_allowed": False,
            },
            "disclaimer": "Unsigned private status, not a scan permit or consent receipt.",
        }
        body = json.dumps(
            payload, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ) + "\n"
        return Response(
            body, content_type="application/json; charset=utf-8",
            extra_headers=[(
                "Content-Disposition",
                'attachment; filename="lightup-request-status.json"',
            )],
        )

    def portal_request_receipt(
        self, auth: AuthState, form: dict[str, str],
        client_id: str, request_id: str,
    ) -> Response:
        # The original domain read enforces tenant ownership; the explicit
        # route/client equality is a second boundary for operator portal views.
        viewer = self._portal_context(auth, client_id)
        request = self.store.get_assessment_request(viewer, request_id)
        if request.client_id != client_id:
            raise TenantIsolationError("cross-tenant request receipt denied")
        awaiting = request.status in {
            RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
        }
        if awaiting:
            next_step = "An independent operator still needs to review this request."
        elif request.status is RequestStatus.APPROVED:
            next_step = (
                "The request was approved for scope review only. A separate, "
                "current scope grant, consent, revocation check and HUMAN GO "
                "are still required before any testing."
            )
        elif request.status is RequestStatus.REJECTED:
            next_step = (
                "The operator rejected this request. It cannot support a scope "
                "grant or testing; a new client-origin request needs its own "
                "independent review."
            )
        else:
            raise ValueError("unrecognized persisted request decision")
        new_request_link = (
            f'<a href="/portal/{_e(client_id)}#new-request">'
            'Prepare a separate new request</a> · '
            if request.status is RequestStatus.REJECTED and not auth.is_operator
            else ""
        )
        safety_notice = (
            "A rejected request remains closed. No separate approval, consent "
            "or HUMAN GO can turn this request into a scope grant. "
            "Active testing remains locked."
            if request.status is RequestStatus.REJECTED else
            "An approved request is still not a scope grant, separately "
            "verified consent, revocation-at-use check or HUMAN GO. "
            "Active testing remains locked."
        )
        stages = "".join(
            '<li><strong>' + _e(step["label"]) + '</strong> '
            '<span class="badge">' + _e(step["state"].replace("_", " ").lower())
            + '</span><p class="meta">' + _e(step["explanation"]) + '</p></li>'
            for step in _request_progress(request.status)
        )
        body = (
            "<h1>Assessment request status</h1>"
            '<p class="sub">Your request was recorded for human review. '
            'A request never starts a scan or activates tools.</p>'
            '<section class="card"><div class="row">'
            f'<strong>Request {_e(request.request_id)}</strong>'
            f'<span class="badge">{_e(request.status.value)}</span></div>'
            f'<p class="meta">Submitted: {_e(request.submitted_at)}'
            + (f' · Reviewed: {_e(request.reviewed_at)}'
               if request.reviewed_at else '')
            + '</p>'
            '<strong>Requested systems (not verified)</strong>'
            f'<p>{_e(", ".join(request.requested_assets))}</p>'
            f'<p>Requested risk: {_risk(request.requested_risk)}</p>'
            f'<p class="meta">{_e(next_step)}</p>'
            '<h2>Five separate safety steps</h2>'
            '<ol aria-label="Request review and authorization status">'
            f'{stages}</ol>'
            f'<p class="meta">{_e(safety_notice)}</p>'
            f'{new_request_link}'
            f'<a href="/portal/{_e(client_id)}/requests/{_e(request_id)}.json">'
            'Download private request status JSON</a> · '
            f'<a href="/portal/{_e(client_id)}/authorization-plan">'
            'View authorization plan</a> · '
            f'<a href="/portal/{_e(client_id)}">Back to portal</a>'
            '</section>'
        )
        return Response(_page(
            "LightUp — Request status", "requests", body, auth,
            portal_client=client_id,
        ))

    @staticmethod
    def _parse_portal_request_fields(
        form: dict[str, str],
    ) -> tuple[tuple[str, ...], RiskLevel, str]:
        assets = tuple(
            part.strip() for part in form.get("assets", "").split(",")
            if part.strip()
        )
        if not assets:
            raise ValueError("at least one owned/reviewable system is required")
        raw_risk = form.get("risk")
        if raw_risk is None or raw_risk not in {"1", "2", "3", "4"}:
            raise ValueError("a deliberate risk choice from 1 to 4 is required")
        return assets, RiskLevel(int(raw_risk)), form.get("notes", "")

    def portal_preview_request(
        self, auth: AuthState, form: dict[str, str],
        client_id: str,
    ) -> Response:
        # Preview is private and does not persist consent, request or grant.
        if auth.is_operator or auth.context is None or auth.context.client_id != client_id:
            return Response(_page("Forbidden", "",
                                  "<h1>Client session required</h1>", auth),
                            status="403 Forbidden")
        try:
            assets, risk, notes = self._parse_portal_request_fields(form)
        except ValueError:
            # This is a user-editable, non-authorizing preview. Preserve draft
            # values locally in the authenticated HTML response, fully escaped;
            # never persist invalid input or infer scan authority.
            raw_assets = form.get("assets", "")
            raw_notes = form.get("notes", "")
            raw_risk = form.get("risk", "")
            options = "".join(
                f'<option value="{value}"'
                f'{" selected" if raw_risk == str(value) else ""}>'
                f'{_e(label)}</option>'
                for value, label in (
                    (1, "1 — Passive: observation only"),
                    (2, "2 — Low impact: needs separate authorization"),
                    (3, "3 — Standard: needs separate authorization"),
                    (4, "4 — Elevated: needs additional risk review"),
                )
            )
            placeholder = (
                '<option value="" disabled'
                + (' selected' if raw_risk not in {"1", "2", "3", "4"} else '')
                + '>Choose a risk level…</option>'
            )
            correction = (
                "Add at least one system you manage." if not any(
                    part.strip() for part in raw_assets.split(",")
                )
                else "Select one of the four supported risk levels."
            )
            body = (
                '<h1>Check your assessment request</h1>'
                '<p role="alert" class="error">Some details need attention: '
                f'{_e(correction)}</p>'
                '<section class="card">'
                '<p class="meta">Your draft is preserved below. No request '
                'has been submitted and no testing has been activated.</p>'
                f'<form method="post" action="/portal/{_e(client_id)}/requests/preview">'
                f'{self._csrf_field(auth)}'
                '<label for="fix-assets">Systems you manage (comma-separated)</label>'
                f'<input id="fix-assets" name="assets" required '
                f'value="{_e(raw_assets)}" autocomplete="off">'
                '<label for="fix-risk">Requested testing risk</label>'
                f'<select id="fix-risk" name="risk" required>'
                f'{placeholder}{options}</select>'
                '<label for="fix-notes">Context for the reviewer (optional)</label>'
                f'<textarea id="fix-notes" name="notes" rows="3">'
                f'{_e(raw_notes)}</textarea>'
                '<button>Review corrected request</button>'
                '</form></section>'
            )
            return Response(_page(
                "LightUp — Correct assessment request", "portal", body, auth,
                portal_client=client_id,
            ), status="400 Bad Request")

        editable_risks = "".join(
            f'<option value="{value}"{" selected" if int(risk) == value else ""}>'
            f'{_e(label)}</option>'
            for value, label in (
                (1, "1 — Passive: observation only"),
                (2, "2 — Low impact: needs separate authorization"),
                (3, "3 — Standard: needs separate authorization"),
                (4, "4 — Elevated: needs additional risk review"),
            )
        )
        body = (
            "<h1>Review your assessment request</h1>"
            '<p class="sub">Step 2 of 2: check the details before sending '
            'them for HUMAN review. No active test starts here.</p>'
            '<section class="card">'
            '<strong>Systems as entered (ownership not verified)</strong>'
            f'<p>{_e(", ".join(assets))}</p>'
            '<strong>Requested risk</strong>'
            f'<p>{_risk(risk)}</p>'
            '<strong>Notes for the operator</strong>'
            f'<p>{_e(notes) if notes else "None"}</p>'
            '<p class="meta">A submitted request is not permission to scan, '
            'not a recorded scope grant and not verified consent. Additional '
            'human review and safety gates are required.</p>'
            f'<form method="post" action="/portal/{_e(client_id)}/requests">'
            f'{self._csrf_field(auth)}'
            f'<input type="hidden" name="assets" value="{_e(", ".join(assets))}">'
            f'<input type="hidden" name="risk" value="{int(risk)}">'
            f'<textarea name="notes" hidden>{_e(notes)}</textarea>'
            '<button>Send request for human review</button></form>'
            '<details><summary>Edit this request before sending</summary>'
            '<p class="meta">Change the draft and review it again. Nothing '
            'is submitted until you deliberately send the request.</p>'
            f'<form method="post" action="/portal/{_e(client_id)}/requests/preview">'
            f'{self._csrf_field(auth)}'
            '<label for="preview-assets">Systems you manage</label>'
            f'<input id="preview-assets" name="assets" required '
            f'value="{_e(", ".join(assets))}" autocomplete="off">'
            '<label for="preview-risk">Requested testing risk</label>'
            f'<select id="preview-risk" name="risk" required>{editable_risks}</select>'
            '<label for="preview-notes">Context for the reviewer (optional)</label>'
            f'<textarea id="preview-notes" name="notes" rows="3">{_e(notes)}</textarea>'
            '<button class="secondary">Update review</button>'
            '</form></details>'
            f'<p><a href="/portal/{_e(client_id)}">Back to portal</a></p>'
            '</section>'
        )
        return Response(_page(
            "LightUp — Review assessment request", "portal", body, auth,
            portal_client=client_id,
        ))

    def portal_submit_request(self, auth: AuthState, form: dict[str, str],
                              client_id: str) -> Response:
        # Client request provenance must come from the client's real session.
        # Operator access to the portal is deliberately read-only.
        if auth.is_operator or auth.context is None or auth.context.client_id != client_id:
            return Response(_page("Forbidden", "",
                                  "<h1>Client session required</h1>", auth),
                            status="403 Forbidden")
        ctx = auth.context
        assets, risk, notes = self._parse_portal_request_fields(form)
        recorded = self.store.submit_assessment_request(
            ctx,
            requested_assets=assets,
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=risk,
            notes=notes,
        )
        return _redirect(
            f"/portal/{client_id}/requests/{recorded.request_id}"
        )

    # -- shared rendering ------------------------------------------------------

    def _coverage_card(self, ctx: AccessContext, engagement_id: str,
                       engagement_name: str) -> str:
        from ..coverage import CoverageReport, CoverageStatus

        stored = self.store.get_coverage(ctx, engagement_id)
        report = CoverageReport.build(
            {capability: CoverageStatus(status) for capability, status in stored.items()})
        counts = report.counts()
        known_rows = "".join(
            f"<br>{_e(capability)}: {_e(status.value)}"
            for capability, status in report.statuses
            if status is not CoverageStatus.UNKNOWN
        ) or "<br>—"
        warning = ""
        if report.is_materially_unknown:
            warning = ("<p class=\"meta\">Coverage is materially unknown: zero "
                       "findings is <strong>not</strong> a clean bill of health.</p>")
        return (
            "<div class=\"card\"><div class=\"row\">"
            f"<strong>Coverage — {_e(engagement_name)}</strong>"
            f"<span class=\"badge\">{counts['assessed']} assessed · "
            f"{counts['partially_assessed']} partial · "
            f"{counts['unknown']} unknown</span></div>"
            f"{warning}"
            "<details><summary>Per security domain</summary>"
            f"<p class=\"meta\">{known_rows}<br>"
            f"+ {counts['unknown']} domain(s) with unknown coverage</p></details>"
            "</div>"
        )

    def _finding_cards(self, findings, portal: bool = False) -> str:
        if not findings:
            note = (" Zero findings with unknown coverage is not a clean bill of health;"
                    " coverage reporting arrives with the assessment engine.")
            return f"<p class=\"empty\">No findings recorded.{note if portal else ''}</p>"
        cards = []
        for f in findings:
            retest_badge = {
                RetestStatus.FIXED: "<span class=\"badge ok\">Fixed & verified</span>",
                RetestStatus.REGRESSION: "<span class=\"badge lock\">Regression</span>",
                RetestStatus.FIX_PENDING: "<span class=\"badge warn\">Fix pending</span>",
                RetestStatus.NOT_TESTED: "<span class=\"badge\">Retest not run</span>",
            }[f.retest_status]
            evidence = ""
            if not portal and f.evidence_ids:
                evidence = (
                    "<details><summary>Evidence references</summary><p class=\"meta\">"
                    + "<br>".join(_e(e) for e in f.evidence_ids) + "</p></details>"
                )
            cards.append(
                "<div class=\"card\"><div class=\"row\">"
                f"<strong>{_e(f.title)}</strong>{retest_badge}</div>"
                f"<p class=\"meta\">Severity {_e(f.severity.value)} · asset {_e(f.asset)}</p>"
                "<details><summary>Impact</summary>"
                f"<p>{_e(f.impact) or '—'}</p></details>"
                "<details><summary>Fix</summary>"
                f"<p>{_e(f.remediation)}</p></details>"
                f"{evidence}</div>"
            )
        return "".join(cards)


def create_app(store: DomainStore, security: WebSecurity | None = None) -> LightUpWebApp:
    return LightUpWebApp(store, security)
