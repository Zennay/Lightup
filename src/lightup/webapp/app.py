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
        links = [("portal", base, "Overview")]
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
            ("GET", re.compile(r"^/discovery$"), self.discovery, "operator"),
            ("POST", re.compile(r"^/discovery/prospects$"), self.add_prospect, "operator"),
            ("POST", re.compile(r"^/discovery/prospects/(?P<prospect_id>[\w-]+)/status$"),
             self.prospect_status, "operator"),
            ("GET", re.compile(r"^/clients$"), self.clients, "operator"),
            ("POST", re.compile(r"^/clients$"), self.create_client, "operator"),
            ("GET", re.compile(r"^/clients/(?P<client_id>[\w-]+)$"), self.client_detail,
             "operator"),
            ("POST", re.compile(r"^/clients/(?P<client_id>[\w-]+)/engagements$"),
             self.create_engagement, "operator"),
            ("POST", re.compile(r"^/engagements/(?P<engagement_id>[\w-]+)/grants$"),
             self.record_grant, "operator"),
            ("POST", re.compile(
                r"^/engagements/(?P<engagement_id>[\w-]+)/authorization/revoke$"
            ), self.revoke_authorization, "operator"),
            ("GET", re.compile(r"^/assessments$"), self.assessments, "operator"),
            ("POST", re.compile(r"^/assessments/requests/(?P<request_id>[\w-]+)/decision$"),
             self.decide_request, "operator"),
            ("POST", re.compile(r"^/assessments/elevations/(?P<approval_id>[\w-]+)/decision$"),
             self.decide_elevation, "operator"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)$"), self.portal, "portal"),
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
            except (KeyError, ValueError) as exc:
                body = f"<h1>Request failed</h1><p class=\"sub\">{_e(exc)}</p>"
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

    def overview(self, auth: AuthState, form: dict[str, str]) -> Response:
        ctx = auth.context
        clients = self.store.list_clients(ctx)
        requests = self.store.list_assessment_requests(ctx)
        open_requests = [r for r in requests
                         if r.status in {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}]
        engagements = self.store.list_engagements(ctx)
        findings = self.store.list_findings(ctx)
        open_retests = [f for f in findings if f.retest_status is not RetestStatus.FIXED]
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
            "<div class=\"card\"><div class=\"row\"><strong>Active testing</strong>"
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
        csrf = self._csrf_field(auth)
        engagement_cards = []
        for eng in engagements:
            grant = self.store.get_current_grant(ctx, eng.engagement_id)
            grant_badge = ("<span class=\"badge ok\">Authorization current</span>" if grant
                           else "<span class=\"badge warn\">No current authorization</span>")
            grant_detail = ""
            if grant:
                grant_detail = (
                    "<details><summary>Authorization details</summary><p class=\"meta\">"
                    f"Reference {_e(grant.reference)} · approved by {_e(grant.approved_by)}"
                    f"<br>Assets: {_e(', '.join(grant.scope.assets))}"
                    f"<br>Max risk: {_risk(grant.scope.max_risk)}"
                    f"<br>Valid {_e(grant.valid_from.date())} – {_e(grant.valid_until.date())}"
                    "</p>"
                    f"<form method=\"post\" action=\"/engagements/{_e(eng.engagement_id)}/authorization/revoke\">"
                    f"{csrf}"
                    "<label>Revocation reason</label>"
                    "<input name=\"reason\" required "
                    "placeholder=\"Customer withdrew authorization\">"
                    "<button class=\"secondary\">Revoke authorization</button>"
                    "<p class=\"meta\">This immediately withdraws all current and "
                    "scheduled grants for this engagement.</p></form></details>"
                )
            else:
                grant_detail = (
                    "<details><summary>Record authorization grant</summary>"
                    f"<form method=\"post\" action=\"/engagements/{_e(eng.engagement_id)}/grants\">"
                    f"{csrf}"
                    "<label>Approved by (client signatory)</label>"
                    "<input name=\"approved_by\" required>"
                    "<label>Authorization reference</label>"
                    "<input name=\"reference\" required placeholder=\"AUTH-2026-...\">"
                    "<label>Authorized assets (comma-separated)</label>"
                    "<input name=\"assets\" required>"
                    "<label>Excluded assets (comma-separated, optional)</label>"
                    "<input name=\"excluded_assets\">"
                    "<label>Allowed capabilities (comma-separated ids; empty = all)</label>"
                    "<input name=\"capabilities\">"
                    "<label>Maximum risk level</label><select name=\"max_risk\">"
                    "<option value=\"1\">1 — Passive</option>"
                    "<option value=\"2\">2 — Low impact</option>"
                    "<option value=\"3\" selected>3 — Standard</option>"
                    "<option value=\"4\">4 — Elevated</option></select>"
                    "<label>Valid for (days)</label>"
                    "<input name=\"valid_days\" type=\"number\" min=\"1\" max=\"365\" value=\"30\">"
                    "<button>Record grant</button>"
                    "<p class=\"meta\">A grant only authorizes what is listed here. "
                    "Destructive simulation (level 5) is lab-only and cannot be "
                    "granted for client assets.</p></form></details>"
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
            "open client portal</a></p>"
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

    def create_engagement(self, auth: AuthState, form: dict[str, str],
                          client_id: str) -> Response:
        self.store.create_engagement(auth.context, client_id, form.get("name", ""))
        return _redirect(f"/clients/{client_id}")

    def record_grant(self, auth: AuthState, form: dict[str, str],
                     engagement_id: str) -> Response:
        from datetime import datetime, timedelta, timezone

        from ..engagements import ScopeDefinition

        def _csv(name: str) -> tuple[str, ...]:
            return tuple(part.strip() for part in form.get(name, "").split(",")
                         if part.strip())

        max_risk = RiskLevel(int(form.get("max_risk", "3")))
        if max_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
            raise ValueError("destructive simulation cannot be granted for client assets")
        valid_days = max(1, min(365, int(form.get("valid_days", "30"))))
        now = datetime.now(timezone.utc)
        scope = ScopeDefinition(
            assets=_csv("assets"),
            max_risk=max_risk,
            allowed_capabilities=_csv("capabilities"),
            excluded_assets=_csv("excluded_assets"),
        )
        engagement = self.store.get_engagement(auth.context, engagement_id)
        self.store.record_authorization_grant(
            auth.context, engagement_id,
            approved_by=form.get("approved_by", ""),
            reference=form.get("reference", ""),
            scope=scope, valid_from=now,
            valid_until=now + timedelta(days=valid_days),
        )
        return _redirect(f"/clients/{engagement.client_id}")

    def revoke_authorization(self, auth: AuthState, form: dict[str, str],
                             engagement_id: str) -> Response:
        engagement = self.store.get_engagement(auth.context, engagement_id)
        self.store.revoke_engagement_authorization(
            auth.context, engagement_id, form.get("reason", "")
        )
        return _redirect(f"/clients/{engagement.client_id}")

    def assessments(self, auth: AuthState, form: dict[str, str]) -> Response:
        ctx = auth.context
        csrf = self._csrf_field(auth)
        requests = self.store.list_assessment_requests(ctx)
        approvals = [a for a in self.store.list_risk_approvals(ctx)
                     if a.status.value == "pending"]
        request_cards = []
        for r in requests:
            client = self.store.get_client(ctx, r.client_id)
            decision = ""
            if r.status in {RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW}:
                decision = (
                    f'<form class="inline" method="post" '
                    f'action="/assessments/requests/{_e(r.request_id)}/decision">{csrf}'
                    '<input type="hidden" name="decision" value="approve">'
                    "<button>Approve</button></form> "
                    f'<form class="inline" method="post" '
                    f'action="/assessments/requests/{_e(r.request_id)}/decision">{csrf}'
                    '<input type="hidden" name="decision" value="reject">'
                    "<button class=\"secondary\">Reject</button></form>"
                )
            request_cards.append(
                "<div class=\"card\"><div class=\"row\">"
                f"<strong>{_e(client.name)}</strong>"
                f"<span class=\"badge\">{_e(r.status.value)}</span></div>"
                f"<p class=\"meta\">Requested risk: {_risk(r.requested_risk)} · "
                f"mode {_e(r.requested_mode.value)}</p>"
                "<details><summary>Requested assets & notes</summary>"
                f"<p class=\"meta\">Assets: {_e(', '.join(r.requested_assets))}<br>"
                f"Notes: {_e(r.notes) or '—'}</p></details>"
                f"{decision}</div>"
            )
        elevation_cards = []
        for a in approvals:
            elevation_cards.append(
                "<div class=\"card\"><div class=\"row\">"
                f"<strong>Risk elevation to {_risk(a.requested_risk)}</strong>"
                "<span class=\"badge warn\">Step-up approval required</span></div>"
                f"<p class=\"meta\">Engagement {_e(a.engagement_id)} · "
                f"requested by {_e(a.requested_by)}</p>"
                "<details><summary>Justification</summary>"
                f"<p class=\"meta\">{_e(a.justification)}</p></details>"
                f'<form class="inline" method="post" '
                f'action="/assessments/elevations/{_e(a.approval_id)}/decision">{csrf}'
                '<input type="hidden" name="decision" value="approve">'
                "<button>Approve elevation</button></form> "
                f'<form class="inline" method="post" '
                f'action="/assessments/elevations/{_e(a.approval_id)}/decision">{csrf}'
                '<input type="hidden" name="decision" value="deny">'
                "<button class=\"secondary\">Deny</button></form></div>"
            )
        body = (
            "<h1>Assessments</h1>"
            "<p class=\"sub\">Nothing becomes active without a reviewed request, "
            "a recorded authorization grant and an approved risk level.</p>"
            "<h2>Assessment requests</h2>"
            + ("".join(request_cards) or "<p class=\"empty\">No requests.</p>")
            + "<h2>Pending risk elevations</h2>"
            + ("".join(elevation_cards) or "<p class=\"empty\">No pending elevations.</p>")
        )
        return Response(_page("LightUp — Assessments", "assessments", body, auth))

    def decide_request(self, auth: AuthState, form: dict[str, str],
                       request_id: str) -> Response:
        approve = form.get("decision") == "approve"
        self.store.review_assessment_request(auth.context, request_id, approve)
        return _redirect("/assessments")

    def decide_elevation(self, auth: AuthState, form: dict[str, str],
                         approval_id: str) -> Response:
        approve = form.get("decision") == "approve"
        self.store.decide_risk_elevation(auth.context, approval_id, approve)
        return _redirect("/assessments")

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
        requests = self.store.list_assessment_requests(ctx)
        fixed = sum(1 for f in findings if f.retest_status is RetestStatus.FIXED)
        request_rows = "".join(
            "<div class=\"card\"><div class=\"row\">"
            f"<strong>{_e(', '.join(r.requested_assets))}</strong>"
            f"<span class=\"badge\">{_e(r.status.value)}</span></div>"
            f"<p class=\"meta\">Requested risk: {_risk(r.requested_risk)}</p></div>"
            for r in requests
        ) or "<p class=\"empty\">No assessment requests yet.</p>"
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
            + f"<h2>Your assessment requests</h2>{request_rows}"
            "<h2>Request an assessment</h2>"
            "<div class=\"card\">"
            f"<form method=\"post\" action=\"/portal/{_e(client_id)}/requests\">"
            f"{self._csrf_field(auth)}"
            "<label>Assets (comma-separated hostnames/systems you own)</label>"
            "<input name=\"assets\" required>"
            "<label>Requested risk level</label><select name=\"risk\">"
            "<option value=\"1\">1 — Passive</option>"
            "<option value=\"2\">2 — Low impact</option>"
            "<option value=\"3\" selected>3 — Standard</option>"
            "<option value=\"4\">4 — Elevated</option></select>"
            "<label>Notes</label><textarea name=\"notes\" rows=\"3\"></textarea>"
            "<button>Submit request</button>"
            "<p class=\"meta\">Submitting a request starts a review. Active testing "
            "begins only after you provide written authorization and an operator "
            "approves scope and risk.</p></form></div>"
        )
        return Response(_page(f"LightUp — {client.name}", "portal", body, auth,
                              portal_client=client_id))

    def portal_submit_request(self, auth: AuthState, form: dict[str, str],
                              client_id: str) -> Response:
        ctx = self._portal_context(auth, client_id)
        assets = tuple(part.strip() for part in form.get("assets", "").split(",") if part.strip())
        risk = RiskLevel(int(form.get("risk", "3")))
        if risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
            raise ValueError("destructive simulation cannot be requested from the portal")
        self.store.submit_assessment_request(
            ctx,
            requested_assets=assets,
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=risk,
            notes=form.get("notes", ""),
        )
        return _redirect(f"/portal/{client_id}")

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
