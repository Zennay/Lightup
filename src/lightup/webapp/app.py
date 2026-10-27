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
header .wrap { display:flex; flex-wrap:wrap; align-items:center; gap:18px;
               padding-top:12px; padding-bottom:12px; }
.brand { font-weight:650; letter-spacing:.02em; }
.skip-link { position:absolute; left:12px; top:-120px; z-index:20;
             background:var(--card); color:var(--ink); padding:10px 14px;
             border:3px solid var(--accent); border-radius:8px; }
.skip-link:focus { top:10px; }
nav { display:flex; gap:8px 14px; flex-wrap:wrap; align-items:center; }
nav a { color:var(--muted); display:inline-flex; min-height:44px;
        align-items:center; padding:9px 4px; }
nav a.active { color:var(--ink); border-bottom:2px solid var(--accent); }
nav form { display:inline; }
nav button { background:none; border:0; color:var(--muted); cursor:pointer;
             font:inherit; padding:0; }
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,
textarea:focus-visible,summary:focus-visible {
  outline:3px solid var(--accent); outline-offset:3px;
}
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
.risk-guide { border:1px solid var(--line); background:#f8faf9;
              border-radius:10px; padding:12px 14px; margin:8px 0 16px; }
.risk-guide summary { color:var(--ink); font-weight:650; min-height:24px; }
.risk-guide dl { display:grid; grid-template-columns:minmax(100px, 130px) 1fr;
                 gap:10px 16px; margin:16px 0 8px; }
.risk-guide dt { color:var(--ink); font-weight:650; }
.risk-guide dd { margin:0; color:var(--muted); }
.risk-guide .meta { margin-bottom:0; }
.next-action { border-left:4px solid var(--lock); background:#fffaf7; }
.next-action h2 { margin:10px 0 4px; font-size:1.2rem; }
.task-links { display:grid; grid-template-columns:repeat(3,minmax(0,1fr));
              gap:12px; margin:0 0 28px; }
.task-links a { display:block; min-height:96px; padding:14px 16px;
                border-radius:10px; border:1px solid var(--line);
                background:var(--card); color:var(--ink); }
.task-links strong, .task-links span { display:block; }
.task-links span { color:var(--muted); font-size:.85rem; margin-top:4px; }
.task-links a:hover { border-color:var(--accent); }
.grant-request { padding-top:12px; border-top:1px solid var(--line); margin-top:20px; }
.grant-request h3 { font-size:1rem; margin:4px 0 10px; }
.grant-step { min-width:0; margin:16px 0; padding:14px;
              border:1px solid var(--line); border-radius:10px; }
.grant-step legend { color:var(--ink); font-weight:650; padding:0 6px; }
.grant-step label { display:block; margin-top:12px; }
.grant-step input, .grant-step select { max-width:100%; }
.risk-options { min-width:0; border:0; padding:0; margin:12px 0 18px; }
.risk-options legend { color:var(--ink); font-weight:650; padding:0; }
.risk-cards { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin:10px 0; }
.risk-cards .risk-choice { display:flex; align-items:flex-start; gap:10px;
                           cursor:pointer; min-height:92px; padding:12px;
                           border:1px solid var(--line); border-radius:10px;
                           background:var(--card); color:var(--ink); }
.risk-cards input[type="radio"] { flex:0 0 20px; width:20px; height:20px;
                                  min-height:20px; padding:0; margin:3px 0 0;
                                  accent-color:var(--accent); }
.risk-cards .risk-choice:focus-within { outline:3px solid var(--accent); outline-offset:2px; }
.risk-cards strong, .risk-cards small { display:block; }
.risk-cards small { font-size:.83rem; line-height:1.45; color:var(--muted); margin-top:4px; }
@media (max-width:560px) {
  .wrap { padding-left:16px; padding-right:16px; }
  header .wrap { display:block; padding-top:12px; padding-bottom:12px; }
  nav { margin-top:8px; gap:4px 12px; }
  nav a { padding:10px 4px; }
  nav button { min-height:44px; padding:8px 4px; }
  .grid { grid-template-columns:minmax(0,1fr); }
  .task-links { grid-template-columns:minmax(0,1fr); }
  .task-links a { min-height:74px; }
  .risk-cards { grid-template-columns:minmax(0,1fr); }
  .risk-cards .risk-choice { min-height:72px; }
  .card { padding:14px; }
  .row { align-items:flex-start; }
  .risk-guide dl { grid-template-columns:1fr; gap:4px; }
  .risk-guide dd { margin-bottom:12px; }
}
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _risk(level: RiskLevel) -> str:
    return _e(_RISK_LABELS[level])


def _risk_choice_guide() -> str:
    """Plain-language risk comparison; information only, never a permit."""
    return (
        '<details class="risk-guide">'
        '<summary>Compare the testing risk levels and required reviews</summary>'
        '<dl>'
        '<dt>1 · Passive</dt><dd>Observation and evidence review only. '
        'Submitting this choice does not approve contacting a system.</dd>'
        '<dt>2 · Low impact</dt><dd>Would allow only narrowly scoped '
        'non-destructive checks after a separate explicit authorization.</dd>'
        '<dt>3 · Standard</dt><dd>Would require specific reviewed scope and '
        'consent for more involved checks. Never implied by a request.</dd>'
        '<dt>4 · Elevated</dt><dd>Requires a further independent risk '
        'decision before any future consideration of activity.</dd>'
        '</dl>'
        '<p class="meta">Every level still needs independently verified '
        'ownership, a reviewed client-origin request, a specific current '
        'grant, consent, revocation checks and explicit HUMAN GO. '
        'All target testing is locked in this build.</p>'
        '</details>'
    )


_RISK_CHOICES = (
    ("1", "Passive", "Review existing evidence. This form does not contact systems."),
    ("2", "Low impact", "Limited checks would need separate verified authorization."),
    ("3", "Standard", "Broader checks would need exact reviewed scope and consent."),
    ("4", "Elevated", "An additional independent human risk decision is required."),
)


def _risk_choice_cards(prefix: str, selected: str = "",
                       invalid: bool = False) -> str:
    """Native radio choices keep the cost of each risk level visible.

    The persisted form contract remains the same four risk values.
    Selecting here never records consent, a grant or testing authority.
    """
    if prefix not in {"request", "retry", "fix", "preview"}:
        raise ValueError("unsupported request risk field")
    help_id = f"{prefix}-risk-help"
    described_by = help_id + (" fix-risk-error" if invalid else "")
    options = "".join(
        '<label class="risk-choice">'
        f'<input type="radio" name="risk" value="{value}"'
        + (' checked' if selected == value else '')
        + (' required' if value == "1" else '')
        + (' aria-invalid="true"' if invalid else '')
        + '><span>'
        f'<strong>{_e(value)} — {_e(title)}</strong>'
        f'<small>{_e(explanation)}</small></span></label>'
        for value, title, explanation in _RISK_CHOICES
    )
    return (
        f'<fieldset class="risk-options" id="{_e(prefix)}-risk"'
        f' aria-describedby="{_e(described_by)}"'
        + (' tabindex="-1" aria-invalid="true"' if invalid else '')
        + '><legend>Requested testing risk</legend>'
        f'<div class="risk-cards">{options}</div>'
        f'<p class="meta" id="{_e(help_id)}">A risk choice is only a request. '
        'It never permits testing; current scope, consent, revocation checks '
        'and HUMAN GO are separate.</p></fieldset>'
    )


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
        f'<a href="{_e(href)}" class="{"active" if key == nav else ""}"'
        + (' aria-current="page"' if key == nav else '')
        + f'>{_e(label)}</a>'
        for key, href, label in links
    ) + logout
    if nav == "login":
        nav_html = ""
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>"
        '<a class="skip-link" href="#main-content">Skip to main content</a>'
        f"<header><div class=\"wrap\"><span class=\"brand\">{_e(brand)}</span>"
        f'<nav aria-label="{"Client portal" if portal_client is not None else "Operator"} navigation">'
        f"{nav_html}</nav></div></header>"
        f'<main id="main-content" tabindex="-1"><div class="wrap">{body}</div>'
        "</main></body></html>"
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
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/requests/(?P<request_id>[\w-]+)/new-draft$"),
             self.portal_new_draft_from_rejection, "portal"),
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

    def _client_scoped_evidence(self, ctx: AccessContext, client_id: str):
        """Use one fail-closed provenance boundary for both client views.

        Explicit tenant filters protect operator screens as well as portal
        screens. The original domain joins still need their separate
        source-owner review before any release.
        """
        engagements = self.store.list_engagements(ctx, client_id)
        findings = self.store.list_findings(ctx, client_id=client_id)
        engagement_ids = {item.engagement_id for item in engagements}
        if any(item.client_id != client_id for item in engagements):
            raise TenantIsolationError("cross-tenant client engagement denied")
        if any(
            item.client_id != client_id or item.engagement_id not in engagement_ids
            for item in findings
        ):
            raise TenantIsolationError("cross-tenant client finding linkage denied")
        return engagements, findings

    def client_detail(self, auth: AuthState, form: dict[str, str],
                      client_id: str) -> Response:
        ctx = auth.context
        client = self.store.get_client(ctx, client_id)
        engagements, findings = self._client_scoped_evidence(ctx, client_id)
        client_requests = self.store.list_assessment_requests(ctx, client_id)
        if any(item.client_id != client_id for item in client_requests):
            raise TenantIsolationError("cross-tenant operator request list denied")
        approved_requests = tuple(
            request for request in client_requests
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
        # One original client-specific human-decision worklist, rather than
        # forcing operators to search the global review inbox by opaque IDs.
        valid_request_states = {
            RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
            RequestStatus.APPROVED, RequestStatus.REJECTED,
        }
        if any(item.status not in valid_request_states for item in client_requests):
            raise ValueError("unknown persisted assessment request state")
        waiting_requests = sorted(
            (
                item for item in client_requests
                if item.status in {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}
            ),
            key=lambda item: (item.created_at, item.request_id),
        )
        decided_requests = sorted(
            (
                item for item in client_requests
                if item.status in {RequestStatus.APPROVED, RequestStatus.REJECTED}
            ),
            key=lambda item: (item.created_at, item.request_id),
            reverse=True,
        )

        def request_card(item) -> str:
            pending = item.status in {
                RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
            }
            action = (
                "Open independent HUMAN review" if pending
                else "Read recorded human decision"
            )
            return (
                '<section class="card"><div class="row">'
                f'<strong>Request {_e(item.request_id[:8])}</strong>'
                f'<span class="badge">{_e(item.status.value)}</span></div>'
                f'<p class="meta">Submitted {_e(item.created_at)} · '
                f'Risk {_risk(item.requested_risk)} · '
                f'Mode {_e(item.requested_mode.value)}</p>'
                '<details><summary>Requested systems and client notes</summary>'
                f'<p class="meta">Systems: {_e(", ".join(item.requested_assets))}</p>'
                f'<p class="meta">Notes: {_e(item.notes) or "None"}</p>'
                '</details>'
                f'<a href="/assessments/requests/{_e(item.request_id)}/review">'
                f'{action}</a></section>'
            )

        request_section = (
            f'<h2>Client-origin requests · {len(client_requests)} total</h2>'
            '<p class="sub">A client request can receive an independent human '
            'decision; it never grants scope, verifies consent or starts testing.</p>'
            f'<h3>Awaiting independent review ({len(waiting_requests)})</h3>'
            + ("".join(request_card(item) for item in waiting_requests)
               or '<p class="empty">No client requests are awaiting review.</p>')
            + f'<details><summary>Recorded request decisions ({len(decided_requests)})</summary>'
            + ("".join(request_card(item) for item in decided_requests)
               or '<p class="empty">No human decisions recorded yet.</p>')
            + '</details>'
        )

        # Keep every original risk decision on the same operator client dossier.
        # The domain list is operator-wide: select by BOTH authoritative
        # engagement ownership and duplicated risk-row client ownership.
        engagement_by_id = {item.engagement_id: item for item in engagements}
        client_risk_reviews = []
        valid_risk_states = {"pending", "approved", "denied"}
        for item in self.store.list_risk_approvals(ctx):
            linked_engagement = engagement_by_id.get(item.engagement_id)
            if item.client_id != client_id and linked_engagement is None:
                continue
            if linked_engagement is None or item.client_id != client_id:
                raise TenantIsolationError(
                    "cross-tenant client risk approval linkage denied"
                )
            if item.status.value not in valid_risk_states:
                raise ValueError("unknown persisted risk review state")
            client_risk_reviews.append(item)
        pending_risk_reviews = sorted(
            (item for item in client_risk_reviews if item.status.value == "pending"),
            key=lambda item: (item.created_at, item.approval_id),
        )
        decided_risk_reviews = sorted(
            (item for item in client_risk_reviews if item.status.value != "pending"),
            key=lambda item: (item.created_at, item.approval_id),
            reverse=True,
        )

        def risk_card(item) -> str:
            engagement = engagement_by_id[item.engagement_id]
            pending = item.status.value == "pending"
            action = (
                "Open independent HUMAN risk review" if pending
                else "Read recorded HUMAN risk decision"
            )
            decision_note = (
                f' · Decided {_e(item.decided_at or "Not recorded")}'
                if not pending else ""
            )
            return (
                '<section class="card"><div class="row">'
                f'<strong>{_e(engagement.name)} · Risk {_risk(item.requested_risk)}</strong>'
                f'<span class="badge">{_e(item.status.value)}</span></div>'
                f'<p class="meta">Requested {_e(item.created_at)} · '
                f'By {_e(item.requested_by)}{decision_note}</p>'
                '<details><summary>Original risk justification</summary>'
                f'<p class="meta">{_e(item.justification)}</p></details>'
                f'<a href="/assessments/elevations/{_e(item.approval_id)}/review">'
                f'{action}</a></section>'
            )

        risk_section = (
            f'<h2>Engagement risk decisions · {len(client_risk_reviews)} total</h2>'
            '<p class="sub">A risk-elevation decision never widens a grant, '
            'verifies client consent or enables execution.</p>'
            f'<h3>Awaiting risk decision ({len(pending_risk_reviews)}) · oldest first</h3>'
            + ("".join(risk_card(item) for item in pending_risk_reviews)
               or '<p class="empty">No elevated-risk decisions awaiting review.</p>')
            + f'<details><summary>Recorded risk decisions ({len(decided_risk_reviews)})</summary>'
            + ("".join(risk_card(item) for item in decided_risk_reviews)
               or '<p class="empty">No recorded risk decisions yet.</p>')
            + '</details>'
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
                    # Unique labels remain associated with their controls even
                    # when several approved requests share one engagement.
                    field_prefix = f"grant-{eng.engagement_id}-{request.request_id}"
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
                        f'<section class="grant-request" aria-labelledby="{_e(field_prefix)}-heading">'
                        f'<h3 id="{_e(field_prefix)}-heading">Engagement: {_e(eng.name)}</h3>'
                        '<div class="row">'
                        '<strong>Independent client request approved for scope review</strong>'
                        '<span class="badge lock">PLAN ONLY · no execution</span></div>'
                        f'<p class="meta">Client-requested risk ceiling: '
                        f'{_risk(request.requested_risk)}. A recorded request decision '
                        'is not verified asset ownership, client consent or HUMAN GO.</p>'
                        '<details><summary>Read original client request and approved asset list</summary>'
                        f'<p class="meta">Request ID: <code>{_e(request.request_id)}</code></p>'
                        f'<p>Original requested assets: {_e(requested_assets)}</p>'
                        '<p class="meta">Use the exact approved asset identifiers; '
                        'never add a destination absent from the original request.</p>'
                        '</details>'
                        f'<form method="post" action="/engagements/{_e(eng.engagement_id)}/grants"'
                        f' aria-describedby="{_e(field_prefix)}-hold">'
                        f'{csrf}'
                        f'<input type="hidden" name="approved_request_id" value="{_e(request.request_id)}">'
                        '<fieldset class="grant-step">'
                        '<legend>1. Identify the authorization record</legend>'
                        f'<label for="{_e(field_prefix)}-approved-by">'
                        'Client signatory recorded on the authorization</label>'
                        f'<input id="{_e(field_prefix)}-approved-by" name="approved_by" '
                        'autocomplete="off" required>'
                        '<p class="meta">Recording a signatory name does not independently '
                        'verify their identity or consent.</p>'
                        f'<label for="{_e(field_prefix)}-reference">Authorization reference</label>'
                        f'<input id="{_e(field_prefix)}-reference" name="reference" required '
                        'autocomplete="off" placeholder="Document or agreement reference">'
                        '</fieldset>'
                        '<fieldset class="grant-step">'
                        '<legend>2. Restrict the requested scope</legend>'
                        f'<label for="{_e(field_prefix)}-assets">Authorized assets '
                        '(exact approved subset; comma-separated)</label>'
                        f'<input id="{_e(field_prefix)}-assets" name="assets" '
                        f'aria-describedby="{_e(field_prefix)}-assets-help" '
                        'autocomplete="off" required>'
                        f'<p class="meta" id="{_e(field_prefix)}-assets-help">'
                        'Copy only the explicitly authorized asset identifiers '
                        'from the original request shown above. An empty or wider '
                        'scope is not acceptable.</p>'
                        f'<label for="{_e(field_prefix)}-excluded">Excluded assets (optional)</label>'
                        f'<input id="{_e(field_prefix)}-excluded" name="excluded_assets" '
                        'autocomplete="off">'
                        f'<label for="{_e(field_prefix)}-capabilities">'
                        'Allowed planning capability IDs (comma-separated)</label>'
                        f'<input id="{_e(field_prefix)}-capabilities" name="capabilities" '
                        f'aria-describedby="{_e(field_prefix)}-capabilities-help" '
                        'autocomplete="off" required>'
                        f'<p class="meta" id="{_e(field_prefix)}-capabilities-help">'
                        'Only explicitly named, known planning capabilities '
                        'are accepted. Listing one never enables execution.</p>'
                        '<details><summary>See available planning capability IDs</summary>'
                        f'<ul>{capability_guide}</ul></details>'
                        '</fieldset>'
                        '<fieldset class="grant-step">'
                        '<legend>3. Set a narrower risk ceiling and expiry</legend>'
                        f'<label for="{_e(field_prefix)}-max-risk">Maximum recorded risk level</label>'
                        f'<select id="{_e(field_prefix)}-max-risk" name="max_risk" required '
                        f'aria-describedby="{_e(field_prefix)}-risk-help">'
                        '<option value="" selected disabled>Choose within approved request</option>'
                        f'{risk_options}</select>'
                        f'<p class="meta" id="{_e(field_prefix)}-risk-help">'
                        'Only levels at or below the original approved request are '
                        'shown. Elevated risk still requires an independent risk '
                        'decision; level 5 is never allowed for client assets.</p>'
                        f'<label for="{_e(field_prefix)}-days">Record validity (days)</label>'
                        f'<input id="{_e(field_prefix)}-days" name="valid_days" '
                        'type="number" min="1" max="365" inputmode="numeric" required>'
                        '</fieldset>'
                        f'<p class="meta" id="{_e(field_prefix)}-hold">'
                        '<strong>Stop line:</strong> recording this request-bound scope '
                        'does not verify current consent, revocation at use or HUMAN GO. '
                        'No scan, target contact or activation is available here.</p>'
                        '<button>Record this request-bound scope only</button>'
                        '</form></section>'
                    )
                grant_detail = (
                    '<details><summary>Record authorization grant</summary>'
                    '<p class="meta">Choose an original approved client request for each '
                    'record. The three review steps distinguish signatory provenance, '
                    'the exact asset/capability boundaries, and expiry. None of these '
                    'form inputs independently proves consent or permits testing.</p>'
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
            + request_section
            + risk_section
            + "<h2>Engagements</h2>"
            + ("".join(engagement_cards) or "<p class=\"empty\">No engagements yet.</p>")
            + f"<h2>New engagement</h2>{new_engagement}"
            + "<h2>Coverage</h2>"
            + ("".join(self._coverage_card(ctx, e.engagement_id, e.name)
                       for e in engagements)
               or "<p class=\"empty\">No engagements yet.</p>")
            + f"<h2>Findings · human remediation priorities</h2>"
              f"{self._finding_cards(findings)}"
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
        )
        risk_reviews = self.store.list_risk_approvals(ctx)
        allowed_risk_states = {"pending", "approved", "denied"}
        if any(item.status.value not in allowed_risk_states for item in risk_reviews):
            raise ValueError("unknown persisted risk decision state")
        approvals = sorted(
            (item for item in risk_reviews if item.status.value == "pending"),
            key=lambda item: (item.created_at, item.approval_id),
        )
        decided_risk_reviews = sorted(
            (item for item in risk_reviews if item.status.value in {"approved", "denied"}),
            key=lambda item: (item.created_at, item.approval_id),
            reverse=True,
        )
        # Resolve names once from original operator-visible tenant records.
        # A mismatched engagement/client link must never be presented as trusted.
        risk_clients = {
            client.client_id: client.name for client in self.store.list_clients(ctx)
        }
        risk_engagements = {
            engagement.engagement_id: engagement
            for engagement in self.store.list_engagements(ctx)
        }

        def risk_context(item) -> str:
            engagement = risk_engagements.get(item.engagement_id)
            client_name = risk_clients.get(item.client_id)
            if (engagement is None or engagement.client_id != item.client_id
                    or client_name is None):
                raise TenantIsolationError("risk review tenant linkage invalid")
            return (
                f'<a href="/clients/{_e(item.client_id)}">{_e(client_name)}</a>'
                f' · {_e(engagement.name)}'
            )

        pending_requests = []
        decided_requests = []
        # One chronological HUMAN queue across client requests and engagement
        # risk elevations. Separate counters/history remain informational only.
        pending_decisions = []
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
                f'<strong>Client assessment · {_e(client.name)}</strong>'
                f'<span class="badge">{_e(request.status.value)}</span></div>'
                f'<p class="meta">Submitted {_e(request.created_at)}'
                + (f' · Decided {_e(request.decided_at)}'
                   if request.decided_at else '')
                + f' · Requested risk: {_risk(request.requested_risk)}'
                f' · Mode {_e(request.requested_mode.value)}'
                f' · By {_e(request.requested_by)}</p>'
                '<details><summary>Requested systems and notes</summary>'
                f'<p class="meta">Systems: {_e(", ".join(request.requested_assets))}</p>'
                f'<p class="meta">Notes: {_e(request.notes) or "—"}</p></details>'
                f'<a href="/assessments/requests/{_e(request.request_id)}/review">'
                f'{action}</a> · '
                f'<a href="/clients/{_e(request.client_id)}/authorization-plan">'
                'Review client source and scope context</a></section>'
            )
            if pending:
                pending_requests.append(card)
                pending_decisions.append((
                    request.created_at, request.request_id, "assessment", card,
                ))
            else:
                # The pending worklist runs oldest-first; history remains newest-first.
                decided_requests.insert(0, card)

        elevation_cards = []
        for approval in approvals:
            card = (
                '<section class="card"><div class="row">'
                f'<strong>Risk elevation to {_risk(approval.requested_risk)}</strong>'
                '<span class="badge warn">Human decision required</span></div>'
                f'<p class="meta">{risk_context(approval)} · '
                f'Engagement ID {_e(approval.engagement_id)} · '
                f'Requested {_e(approval.created_at)} · '
                f'By {_e(approval.requested_by)}</p>'
                '<details><summary>Justification</summary>'
                f'<p class="meta">{_e(approval.justification)}</p></details>'
                f'<a href="/assessments/elevations/{_e(approval.approval_id)}/review">'
                'Open deliberate risk review</a> · '
                f'<a href="/clients/{_e(approval.client_id)}/authorization-plan">'
                'Review client source and scope context</a></section>'
            )
            elevation_cards.append(card)
            pending_decisions.append((
                approval.created_at, approval.approval_id, "risk", card,
            ))
        # Preserve deterministic FIFO fairness even when two requests arrive
        # at the same instant, without inventing urgency or scan authority.
        pending_decisions.sort(key=lambda entry: (entry[0], entry[1], entry[2]))
        risk_history_cards = []
        for decision in decided_risk_reviews:
            risk_history_cards.append(
                '<section class="card"><div class="row">'
                f'<strong>Risk elevation to {_risk(decision.requested_risk)}</strong>'
                f'<span class="badge">{_e(decision.status.value)}</span></div>'
                f'<p class="meta">{risk_context(decision)} · '
                f'Engagement ID {_e(decision.engagement_id)} · '
                f'Recorded by {_e(decision.decided_by or "Not recorded")} · '
                f'At {_e(decision.decided_at or "Not recorded")}</p>'
                '<p class="meta">This decision does not extend a scope grant '
                'or authorize testing.</p>'
                f'<a href="/assessments/elevations/{_e(decision.approval_id)}/review">'
                'Open recorded risk decision</a></section>'
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
            f'<section class="card"><div class="kpi">{len(risk_history_cards)}</div>'
            '<div class="kpi-label">Recorded risk decisions</div></section>'
            '</div>'
            f'<h2>One human-review queue ({len(pending_decisions)}) · oldest first</h2>'
            '<p class="sub">Both original client assessment requests and '
            'engagement risk elevations are ordered by submission time. '
            'A HUMAN review here never creates a scope grant or permission to test.</p>'
            + ("".join(entry[3] for entry in pending_decisions) or
               '<p class="empty">No original requests or elevated-risk decisions '
               'awaiting review.</p>')
            + f'<details><summary>Decided request history ({len(decided_requests)})</summary>'
            + ("".join(decided_requests) or
               '<p class="empty">No previous human request decisions.</p>')
            + '</details>'
            + f'<details><summary>Decided risk-elevation history ({len(risk_history_cards)})</summary>'
            + ("".join(risk_history_cards) or
               '<p class="empty">No previous human risk decisions.</p>')
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
        decision_receipt = (
            '<section class="card" aria-labelledby="request-decision-heading">'
            '<h2 id="request-decision-heading">Recorded human decision</h2>'
            f'<p>Outcome: <strong>{_e(request.status.value)}</strong></p>'
            f'<p class="meta">Recorded by: {_e(request.decided_by or "Not recorded")} · '
            f'At: {_e(request.decided_at or "Not recorded")}</p>'
            '<p class="meta">This decision is not a scope grant, verified consent, '
            'revocation-at-use proof or permission to test.</p></section>'
            if not pending else ""
        )
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
            f'<strong>Submitted:</strong> {_e(request.created_at)}</p>'
            f'<p><strong>Notes:</strong> {_e(request.notes) or "None"}</p>'
            f'<p><a href="/clients/{_e(request.client_id)}/authorization-plan">'
            'Read this client’s original requests, grant and scope context '
            'before deciding (plan-only)</a></p>'
            '<p class="meta">Reviewing this request never verifies system '
            'ownership, action-time revocation or HUMAN GO.</p></section>'
            + decision_receipt
            + (controls or '<p class="empty">Decision already recorded; '
               'no further decision is available here.</p>')
            + '<p><a href="/assessments">Back to operator reviews</a></p>'
        )
        return Response(_page(
            "LightUp — Review request", "assessments", body, auth,
        ))

    def _risk_review_record(self, ctx: AccessContext, approval_id: str):
        """Resolve the source engagement before presenting or posting a review.

        This is a WSGI defense-in-depth guard, not the atomic domain decision
        invariant tracked separately in scope issue #1275.
        """
        decision = next(
            (item for item in self.store.list_risk_approvals(ctx)
             if item.approval_id == approval_id), None,
        )
        if decision is None:
            raise KeyError("risk review not found")
        engagement = self.store.get_engagement(ctx, decision.engagement_id)
        if decision.client_id != engagement.client_id:
            raise TenantIsolationError("risk approval tenant linkage invalid")
        return decision, engagement

    def review_elevation_page(
        self, auth: AuthState, form: dict[str, str], approval_id: str,
    ) -> Response:
        ctx = auth.context
        decision, engagement = self._risk_review_record(ctx, approval_id)
        client = self.store.get_client(ctx, decision.client_id)
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
        elevation_receipt = (
            '<section class="card" aria-labelledby="elevation-decision-heading">'
            '<h2 id="elevation-decision-heading">Recorded risk decision</h2>'
            f'<p>Outcome: <strong>{_e(decision.status.value)}</strong></p>'
            f'<p class="meta">Recorded by: {_e(decision.decided_by or "Not recorded")} · '
            f'At: {_e(decision.decided_at or "Not recorded")}</p>'
            '<p class="meta">A risk decision never widens a scope grant, '
            'verifies consent or permits execution.</p></section>'
            if decision.status.value != "pending" else ""
        )
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
            '<p class="meta"><a href="/clients/'
            f'{_e(decision.client_id)}/authorization-plan">'
            'Read this client’s request, scope and grant evidence (plan-only)</a></p>'
            '<p class="meta">The original reviewed client request, scope grant, '
            'consent and revocation-at-use remain independent prerequisites.</p>'
            '</section>'
            + elevation_receipt
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
        # Fail closed for direct POSTs that bypass the review HTML. The original
        # DomainStore still needs its separate same-transaction #1275 repair.
        self._risk_review_record(auth.context, approval_id)
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
        # Both the operator's client dossier and tenant portal use the
        # same explicit client-scoped evidence and relationship validation.
        engagements, findings = self._client_scoped_evidence(ctx, client_id)
        # Keep the overview minimal: raw scope assets belong only to the
        # authenticated per-request receipt, not a default landing screen.
        requests = self.store.list_assessment_requests(ctx, client_id)
        if any(item.client_id != client_id for item in requests):
            raise TenantIsolationError("cross-tenant portal overview denied")
        ordered_requests = sorted(
            requests, key=lambda item: (item.created_at, item.request_id),
            reverse=True,
        )
        # Coverage is evidence about specific registered capabilities, not a
        # confidence score. Surface its gaps before displaying any zero-finding
        # or fixed-count KPI, using the same original tenant-bound store.
        from ..coverage import CoverageReport, CoverageStatus

        coverage_reports = []
        for engagement in engagements:
            stored = self.store.get_coverage(ctx, engagement.engagement_id)
            report = CoverageReport.build({
                capability: CoverageStatus(status)
                for capability, status in stored.items()
            })
            coverage_reports.append((engagement, report))
        coverage_counts = [report.counts() for _, report in coverage_reports]
        assessed_domains = sum(counts["assessed"] for counts in coverage_counts)
        partial_domains = sum(
            counts["partially_assessed"] for counts in coverage_counts
        )
        unknown_domains = sum(counts["unknown"] for counts in coverage_counts)
        unapproved_domains = sum(
            counts["not_authorized"] for counts in coverage_counts
        )
        if not coverage_reports:
            coverage_message = (
                "No engagements or assessed capability coverage are recorded. "
                "Zero findings cannot be interpreted as a clean bill of health."
            )
        elif unknown_domains:
            coverage_message = (
                "Some security domains have unknown coverage. Neither a low "
                "finding count nor a recorded fix establishes their safety."
            )
        else:
            coverage_message = (
                "Coverage states are recorded, but they do not prove that "
                "every system is safe or authorize additional testing."
            )
        coverage_overview = (
            '<section class="card" aria-labelledby="coverage-summary-heading">'
            '<span class="badge warn">Evidence, not a security score</span>'
            '<h2 id="coverage-summary-heading">What has actually been assessed?</h2>'
            f'<p>{_e(coverage_message)}</p>'
            '<div class="grid">'
            f'<div><strong>{assessed_domains}</strong><p class="meta">Assessed capability entries</p></div>'
            f'<div><strong>{partial_domains}</strong><p class="meta">Partially assessed</p></div>'
            f'<div><strong>{unknown_domains}</strong><p class="meta">Unknown coverage</p></div>'
            f'<div><strong>{unapproved_domains}</strong><p class="meta">Not authorized</p></div>'
            '</div>'
            f'<p class="meta">Across {len(coverage_reports)} recorded engagement(s). '
            'Counts represent registered capabilities per engagement, not tested '
            'systems or verified ownership. Testing remains locked.</p>'
            '<p><a href="#coverage-details">Review coverage by engagement</a></p>'
            '</section>'
        )
        # Surface original scope-blocker facts on the client landing page.
        # A current recorded grant is NOT proof of consent, revocation or GO;
        # reuse the existing read-only authorization plan, never infer a permit.
        from ..authorization_plan import build_client_authorization_plan

        scope_plan = build_client_authorization_plan(self.store, ctx, client_id)
        if (scope_plan.client_id != client_id
                or scope_plan.state != "PLAN_ONLY"
                or scope_plan.execution_allowed is not False):
            raise TenantIsolationError("client scope summary is not tenant-safe")
        known_engagement_ids = {item.engagement_id for item in engagements}
        plan_engagement_ids = {item.engagement_id for item in scope_plan.engagements}
        if (plan_engagement_ids != known_engagement_ids
                or len(plan_engagement_ids) != len(scope_plan.engagements)):
            raise TenantIsolationError("client scope summary engagement mismatch")
        allowed_scope_states = {
            "CURRENT", "EXPIRED", "NOT_YET_VALID", "NOT_RECORDED",
        }
        if any(
            item.scope_record_state not in allowed_scope_states
            or item.decision != "HOLD"
            or item.execution_allowed is not False
            for item in scope_plan.engagements
        ):
            raise ValueError("client scope summary is not fail-closed")
        current_scope_count = sum(
            item.scope_record_state == "CURRENT"
            for item in scope_plan.engagements
        )
        pending_risk_count = sum(
            item.pending_elevations for item in scope_plan.engagements
        )
        # Show the unresolved scope states first, keeping the overview short.
        scope_preview = sorted(
            scope_plan.engagements,
            key=lambda item: (
                item.scope_record_state == "CURRENT",
                item.name.casefold(),
                item.engagement_id,
            ),
        )[:3]
        scope_rows = "".join(
            '<section class="card"><div class="row">'
            f'<strong>{_e(item.name)}</strong>'
            f'<span class="badge warn">{_e(item.scope_record_state.replace("_", " ").lower())}</span></div>'
            f'<p class="meta">Risk reviews awaiting decision: {item.pending_elevations} · '
            f'Separate blocking steps: {len(item.blockers)}</p>'
            '<details><summary>Why this remains HOLD</summary>'
            '<ul>' + "".join(
                f'<li>{_e(reason)}</li>' for reason in item.blockers
            ) + '</ul></details>'
            f'<p><a href="/portal/{_e(client_id)}/authorization-plan'
            f'#engagement-{_e(item.engagement_id)}">'
            'Read original grant details and every safety gate</a></p></section>'
            for item in scope_preview
        )
        scope_board = (
            '<section aria-labelledby="scope-board-heading">'
            '<h2 id="scope-board-heading">Authorization is still on HOLD</h2>'
            f'<p class="sub">{current_scope_count} of {len(scope_plan.engagements)} '
            'engagements have a currently recorded request-bound scope grant; '
            f'{pending_risk_count} risk review(s) await a human decision. '
            'A recorded grant is never independently verified client consent, '
            'revocation-at-use or HUMAN GO. Execution stays OFF.</p>'
            + (scope_rows or
               '<p class="empty">No engagements or scope grants recorded yet.</p>')
            + (f'<p><a href="/portal/{_e(client_id)}/authorization-plan">'
               'See all engagement blockers and the original authorization plan</a></p>'
               if scope_plan.engagements else
               f'<p><a href="/portal/{_e(client_id)}/authorization-plan">'
               'Open the read-only authorization plan</a></p>')
            + '</section>'
        )

        fixed = sum(1 for f in findings if f.retest_status is RetestStatus.FIXED)
        # Counters are for ORIGINAL, tenant-validated recorded findings only;
        # unknown assessment coverage remains prominently shown above.
        outstanding_findings = tuple(
            item for item in findings if item.retest_status is not RetestStatus.FIXED
        )
        urgent_outstanding = sum(
            item.severity.value in {"critical", "high"}
            for item in outstanding_findings
        )
        recorded_regressions = sum(
            item.retest_status is RetestStatus.REGRESSION
            for item in outstanding_findings
        )
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
        # One explicit next action at the top, derived only from persisted
        # request state. This is navigation, never permission or scan readiness.
        pending = sorted(
            (
                item for item in ordered_requests
                if item.status in {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}
            ),
            key=lambda item: (item.created_at, item.request_id),
        )
        if auth.is_operator:
            action_title = "Review client requests"
            action_details = (
                "Operator view is read-only. Independent human decisions "
                "happen in the operator review inbox."
            )
            action_url = "/assessments"
            action_label = "Open operator decision inbox"
        elif pending:
            action_title = "An assessment request is awaiting review"
            action_details = (
                f"{len(pending)} request(s) still need an independent operator "
                "decision. You can follow their private status. No testing "
                "can begin from a submitted request."
            )
            action_url = (
                f"/portal/{_e(client_id)}/requests/{_e(pending[0].request_id)}"
            )
            action_label = "Track the oldest waiting request"
        elif ordered_requests and ordered_requests[0].status is RequestStatus.APPROVED:
            action_title = "Request reviewed — scope still locked"
            action_details = (
                "An operator approved the request for scope review only. "
                "Recorded scope, separate consent, revocation checks and HUMAN "
                "GO are still required; no scan is available."
            )
            action_url = f"/portal/{_e(client_id)}/authorization-plan"
            action_label = "Check the read-only authorization plan"
        elif ordered_requests and ordered_requests[0].status is RequestStatus.REJECTED:
            action_title = "Request rejected — prepare a separate request"
            action_details = (
                "A rejected request cannot support a scope grant. You may "
                "prepare a new client-origin request for independent review."
            )
            action_url = (
                f"/portal/{_e(client_id)}/requests/"
                f"{_e(ordered_requests[0].request_id)}/new-draft"
            )
            action_label = "Review a new draft from rejected request details"
        else:
            action_title = "Start with a review request"
            action_details = (
                "Describe only systems you manage, choose a risk level and "
                "review the draft. An operator must decide independently."
            )
            action_url = f"/portal/{_e(client_id)}#new-request"
            action_label = "Prepare a security assessment request"
        next_action = (
            '<section class="card next-action" aria-labelledby="next-step-heading">'
            '<span class="badge lock">PLAN ONLY · testing locked</span>'
            f'<h2 id="next-step-heading">{_e(action_title)}</h2>'
            f'<p>{_e(action_details)}</p>'
            f'<p><a href="{action_url}">{_e(action_label)}</a></p>'
            '</section>'
        )
        # Three existing client tasks stay visible without scrolling through
        # coverage, grants, and KPI cards. These are navigation only: every
        # engagement remains HOLD and findings are recorded observations.
        task_links = (
            '<nav class="task-links" aria-label="Client task shortcuts">'
            '<a href="#requests-history-heading"><strong>Requests</strong>'
            f'<span>{len(pending)} awaiting human review · {len(requests)} total</span></a>'
            '<a href="#scope-board-heading"><strong>Scope &amp; safety</strong>'
            f'<span>{len(scope_plan.engagements)} engagement(s) · all HOLD</span></a>'
            '<a href="#findings-heading"><strong>Recorded findings</strong>'
            f'<span>{len(outstanding_findings)} need follow-up · '
            f'{urgent_outstanding} critical/high</span></a>'
            '</nav>'
        )
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
                f'{_risk_choice_cards("request")}'
                f'{_risk_choice_guide()}'
                '<label for="request-notes">Context for the reviewer (optional)</label>'
                '<textarea id="request-notes" name="notes" rows="3"></textarea>'
                '<button>Review before sending</button>'
                '<p class="meta">An operator must separately review the request. '
                'Testing stays locked until independent consent, scope validation, '
                'action-time revocation checks and HUMAN GO.</p></form></div>'
            )
        body = (
            f"<h1>{_e(client.name)}</h1>"
            "<p class=\"sub\">Check the next review step, scope limits and recorded evidence. "
            "Active testing is locked.</p>"
            + next_action
            + task_links
            + coverage_overview
            + scope_board
            + "<div class=\"grid\">"
            f"<div class=\"card\"><div class=\"kpi\">{len(findings)}</div>"
            "<div class=\"kpi-label\">Findings</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{fixed}</div>"
            "<div class=\"kpi-label\">Recorded fixed findings</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{urgent_outstanding}</div>"
            "<div class=\"kpi-label\">Critical/high findings needing follow-up</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{recorded_regressions}</div>"
            "<div class=\"kpi-label\">Recorded regressions needing follow-up</div></div>"
            f"<div class=\"card\"><div class=\"kpi\">{len(requests)}</div>"
            "<div class=\"kpi-label\">Assessment requests</div></div>"
            "</div>"
            + request_section
            + f'<h2 id="requests-history-heading">Recent assessment requests</h2><p><a href="/portal/{_e(client_id)}/requests">'
              f'Open all {len(requests)} requests in the private inbox</a></p>'
            + request_rows
            + f"<p><a href=\"/portal/{_e(client_id)}/authorization-plan\">"
              "Review authorization plan (read-only)</a></p>"
            + f'<h2 id="findings-heading">Recorded findings</h2>{self._finding_cards(findings, portal=True)}'
            + '<h2 id="coverage-details">Coverage by engagement</h2>'
            + ("".join(self._coverage_card(ctx, e.engagement_id, e.name, report)
                       for e, report in coverage_reports)
               or '<p class="empty">No engagements yet.</p>')
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
            retry_link = (
                f' · <a href="/portal/{_e(client_id)}/requests/'
                f'{_e(request.request_id)}/new-draft">'
                'Prepare a new draft from these details</a>'
                if request.status is RequestStatus.REJECTED and not auth.is_operator
                else ""
            )
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
                f'{retry_link}'
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
        # Every message comes only from the persisted original request state.
        # Approval remains an approval of the REQUEST, not of target testing.
        if request.status is RequestStatus.SUBMITTED:
            status_title = "Request sent — awaiting review"
            status_summary = "Your request is recorded. No human decision has been made yet."
            next_step = "An independent operator must review the request."
            safety_notice = (
                "There is no operator decision, scope grant, verified consent, "
                "revocation-at-use check or HUMAN GO. Testing remains locked."
            )
        elif request.status is RequestStatus.UNDER_REVIEW:
            status_title = "Request under human review"
            status_summary = "An operator is reviewing the request, not authorizing a scan."
            next_step = "Wait for the independent decision before checking scope requirements."
            safety_notice = (
                "Review in progress is not approval, consent, a scope grant, "
                "revocation-at-use proof or HUMAN GO. Testing remains locked."
            )
        elif request.status is RequestStatus.APPROVED:
            status_title = "Request accepted for scope review"
            status_summary = "The operator approved the request, not active testing."
            next_step = (
                "Read the separate scope and safety requirements. A current "
                "request-bound grant, consent, revocation check and HUMAN GO "
                "would still be required before any testing."
            )
            safety_notice = (
                "Request approval is not a scope grant, independently verified "
                "client consent, revocation-at-use proof or HUMAN GO. "
                "Testing remains locked."
            )
        elif request.status is RequestStatus.REJECTED:
            status_title = "Request rejected — testing remains locked"
            status_summary = "This request cannot support a scope grant."
            next_step = (
                "If needed, prepare a separate client-origin draft and submit "
                "it for its own independent review. The rejection remains recorded."
            )
            safety_notice = (
                "A rejected request stays closed. No later consent or HUMAN GO "
                "can turn this rejected request into a grant. Testing remains locked."
            )
        else:
            raise ValueError("unrecognized persisted request decision")
        if auth.is_operator:
            next_href = "/assessments"
            next_label = "Open operator decision inbox"
            if request.status is RequestStatus.REJECTED:
                next_step = (
                    "Only the client can prepare a separate new request. "
                    "This rejected decision stays recorded and cannot grant scope."
                )
        elif request.status is RequestStatus.REJECTED:
            next_href = f"/portal/{client_id}/requests/{request_id}/new-draft"
            next_label = "Prepare a separate new draft"
        elif request.status is RequestStatus.APPROVED:
            next_href = f"/portal/{client_id}/authorization-plan"
            next_label = "Review the read-only scope and safety plan"
        else:
            next_href = f"/portal/{client_id}/requests"
            next_label = "Track all request statuses"
        stages = "".join(
            '<li><strong>' + _e(step["label"]) + '</strong> '
            '<span class="badge">' + _e(step["state"].replace("_", " ").lower())
            + '</span><p class="meta">' + _e(step["explanation"]) + '</p></li>'
            for step in _request_progress(request.status)
        )
        body = (
            f'<h1>{_e(status_title)}</h1>'
            f'<p class="sub">{_e(status_summary)} A request never starts a scan.</p>'
            '<section class="card next-action" aria-labelledby="request-next-heading">'
            '<span class="badge lock">PLAN ONLY · testing locked</span>'
            '<h2 id="request-next-heading">What happens next?</h2>'
            f'<p>{_e(next_step)}</p>'
            f'<p><a href="{_e(next_href)}">{_e(next_label)}</a></p>'
            '</section>'
            '<section class="card" aria-labelledby="receipt-details-heading">'
            '<h2 id="receipt-details-heading">Your recorded request</h2>'
            '<div class="row">'
            f'<strong>Request {_e(request.request_id)}</strong>'
            f'<span class="badge">{_e(request.status.value)}</span></div>'
            f'<p class="meta">Submitted: {_e(request.created_at)}'
            + (f' · Decided: {_e(request.decided_at)}'
               if request.decided_at else '')
            + '</p>'
            f'<p><strong>Requested risk:</strong> {_risk(request.requested_risk)}</p>'
            '<details><summary>Show submitted systems and reviewer notes</summary>'
            '<p><strong>Systems (ownership not verified)</strong></p>'
            f'<p>{_e(", ".join(request.requested_assets))}</p>'
            '<p><strong>Context for the reviewer</strong></p>'
            f'<p>{_e(request.notes) if request.notes else "None recorded"}</p>'
            '</details>'
            '<p class="meta">' + _e(safety_notice) + '</p>'
            '<details><summary>Five separate review and safety steps</summary>'
            '<ol aria-label="Request review and authorization status">'
            f'{stages}</ol></details>'
            f'<p><a href="/portal/{_e(client_id)}/requests/{_e(request_id)}.json">'
            'Download private request status JSON</a> · '
            f'<a href="/portal/{_e(client_id)}/authorization-plan">'
            'View authorization plan</a> · '
            f'<a href="/portal/{_e(client_id)}">Back to portal</a></p>'
            '</section>'
        )
        return Response(_page(
            f"LightUp — {status_title}", "requests", body, auth,
            portal_client=client_id,
        ))

    def portal_new_draft_from_rejection(
        self, auth: AuthState, form: dict[str, str],
        client_id: str, request_id: str,
    ) -> Response:
        """Reopen rejected client details as a *new*, unsent HUMAN-review draft.

        This read-only GET never edits the rejected original or carries forward
        an approval, consent, authorization grant, or tool activation.
        """
        if auth.is_operator or auth.context is None or auth.context.client_id != client_id:
            return Response(_page(
                "Forbidden", "", "<h1>Client session required</h1>", auth,
            ), status="403 Forbidden")
        original = self.store.get_assessment_request(auth.context, request_id)
        if original.client_id != client_id:
            raise TenantIsolationError("cross-tenant request draft denied")
        if original.status is not RequestStatus.REJECTED:
            raise ValueError("only rejected client requests can be copied into a new draft")

        body = (
            "<h1>Prepare a separate assessment request</h1>"
            '<p class="sub">The previous request remains rejected. The values '
            'below are a convenience only; check that you still manage each '
            'system and deliberately choose the risk again.</p>'
            '<section class="card">'
            f'<p class="meta">Copied from rejected request {_e(request_id)} · '
            f'Previously requested risk: {_risk(original.requested_risk)}</p>'
            '<p class="meta">No new request exists yet. No prior decision, '
            'consent, grant or permission transfers to this draft. Testing '
            'remains locked.</p>'
            f'<form method="post" action="/portal/{_e(client_id)}/requests/preview">'
            f'{self._csrf_field(auth)}'
            '<label for="retry-assets">Systems you manage (comma-separated)</label>'
            f'<input id="retry-assets" name="assets" required autocomplete="off" '
            f'value="{_e(", ".join(original.requested_assets))}" '
            'aria-describedby="retry-assets-help">'
            '<p id="retry-assets-help" class="meta">Remove anything you no longer '
            'own or have explicit permission to request a review for. '
            'Ownership is not verified here.</p>'
            f'{_risk_choice_cards("retry")}'
            f'{_risk_choice_guide()}'
            '<label for="retry-notes">Context for the reviewer (optional)</label>'
            f'<textarea id="retry-notes" name="notes" rows="3">'
            f'{_e(original.notes)}</textarea>'
            '<button>Review a new request before sending</button></form>'
            f'<p><a href="/portal/{_e(client_id)}/requests/'
            f'{_e(request_id)}">Back to rejected request</a></p>'
            '</section>'
        )
        return Response(_page(
            "LightUp — New assessment draft", "requests", body, auth,
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
            missing_assets = not any(
                part.strip() for part in raw_assets.split(",")
            )
            invalid_risk = raw_risk not in {"1", "2", "3", "4"}
            errors = []
            if missing_assets:
                errors.append('<li><a href="#fix-assets">Name at least one '
                              'system you manage.</a></li>')
            if invalid_risk:
                errors.append('<li><a href="#fix-risk">Choose one of the four '
                              'supported risk levels.</a></li>')
            assets_attrs = (
                ' aria-invalid="true" aria-describedby="fix-assets-error"'
                if missing_assets else ""
            )
            body = (
                '<h1>Check your assessment request</h1>'
                '<div role="alert" class="error"><p>Some details need '
                'attention. Follow the links to correct them:</p>'
                f'<ul>{"".join(errors)}</ul></div>'
                '<section class="card">'
                '<p class="meta">Your draft is preserved below. No request '
                'has been submitted and no testing has been activated.</p>'
                f'<form method="post" action="/portal/{_e(client_id)}/requests/preview">'
                f'{self._csrf_field(auth)}'
                '<label for="fix-assets">Systems you manage (comma-separated)</label>'
                f'<input id="fix-assets" name="assets" required '
                f'value="{_e(raw_assets)}" autocomplete="off"{assets_attrs}>'
                + ('<p id="fix-assets-error" class="error">A system is required.</p>'
                   if missing_assets else '')
                + _risk_choice_cards("fix", selected=raw_risk, invalid=invalid_risk)
                + ('<p id="fix-risk-error" class="error">Choose a risk level.</p>'
                   if invalid_risk else '')
                + _risk_choice_guide()
                + '<label for="fix-notes">Context for the reviewer (optional)</label>'
                f'<textarea id="fix-notes" name="notes" rows="3">'
                f'{_e(raw_notes)}</textarea>'
                '<button>Review corrected request</button>'
                '</form></section>'
            )
            return Response(_page(
                "LightUp — Correct assessment request", "portal", body, auth,
                portal_client=client_id,
            ), status="400 Bad Request")

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
            f'{_risk_choice_cards("preview", selected=str(int(risk)))}'
            f'{_risk_choice_guide()}'
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
        try:
            assets, risk, notes = self._parse_portal_request_fields(form)
        except ValueError:
            # A malformed final POST must not silently discard a client's
            # draft. Return to the existing authenticated correction flow;
            # never catch domain authorization/provenance failures here.
            return self.portal_preview_request(auth, form, client_id)
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
                       engagement_name: str, report=None) -> str:
        from ..coverage import CoverageReport, CoverageStatus

        if report is None:
            stored = self.store.get_coverage(ctx, engagement_id)
            report = CoverageReport.build({
                capability: CoverageStatus(status)
                for capability, status in stored.items()
            })
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

        def render_finding(f) -> str:
            retest_badge = {
                RetestStatus.FIXED: "<span class=\"badge ok\">Recorded fixed</span>",
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
            # The portal is authenticated, but its landing view should not
            # shoulder-surf raw system identifiers. The detail disclosure is
            # presentation only; it is NOT a secrecy or authorization boundary.
            asset_detail = (
                "<details><summary>Show affected system</summary>"
                f'<p class="meta">{_e(f.asset)}</p></details>'
                if portal else ""
            )
            asset_meta = "" if portal else f" · asset {_e(f.asset)}"
            return (
                '<section class="card"><div class="row">'
                f"<strong>{_e(f.title)}</strong>{retest_badge}</div>"
                f'<p class="meta">Severity {_e(f.severity.value)}{asset_meta}</p>'
                f"{asset_detail}"
                "<details><summary>Impact</summary>"
                f"<p>{_e(f.impact) or '—'}</p></details>"
                "<details><summary>Fix</summary>"
                f"<p>{_e(f.remediation)}</p></details>"
                f"{evidence}</section>"
            )

        # One read-only HUMAN remediation ordering for both operator and
        # private client views; operators additionally see source references.
        # Neither "fixed" nor a clean visible queue proves assessment coverage
        # or allows another retest.
        severity_priority = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
        }
        def attention_order(f):
            return (
                0 if f.retest_status is RetestStatus.REGRESSION else 1,
                severity_priority.get(f.severity.value, 5),
                f.title.casefold(),
            )

        needs_follow_up = sorted(
            (f for f in findings if f.retest_status is not RetestStatus.FIXED),
            key=attention_order,
        )
        marked_fixed = sorted(
            (f for f in findings if f.retest_status is RetestStatus.FIXED),
            key=attention_order,
        )
        visibility_note = (
            "System names remain collapsed on the client landing view."
            if portal else
            "Operators can inspect source evidence references and affected systems."
        )
        return (
            '<p class="meta">Only original recorded findings are shown. '
            'Regressions come first, then unresolved critical-to-low severity. '
            'A recorded fixed status does not establish full assessment coverage '
            f'or authorize testing. {_e(visibility_note)}</p>'
            f'<h3>Needs HUMAN follow-up ({len(needs_follow_up)})</h3>'
            + ("".join(render_finding(f) for f in needs_follow_up)
               or '<p class="empty">No recorded findings currently need follow-up. '
                  'Check assessment coverage before drawing conclusions.</p>')
            + f'<details><summary>Recorded fixed findings ({len(marked_fixed)})</summary>'
            + ("".join(render_finding(f) for f in marked_fixed)
               or '<p class="empty">No findings are marked fixed yet.</p>')
            + '</details>'
        )


def create_app(store: DomainStore, security: WebSecurity | None = None) -> LightUpWebApp:
    return LightUpWebApp(store, security)
