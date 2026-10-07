"""Optional CSV download extension of the existing secured web shell."""
from __future__ import annotations

import html
import re
import sqlite3

from ..domain import DomainStore, TenantIsolationError
from ..finding_export_service import render_client_findings_csv
from .app import AuthState, LightUpWebApp, Response
from .security import WebSecurity


class FindingExportWebApp(LightUpWebApp):
    def __init__(self, store: DomainStore, security: WebSecurity | None = None):
        super().__init__(store, security)
        self.routes.extend([
            ("GET", re.compile(r"^/portal/(?P<client_id>[\\w-]+)/findings.csv$"),
             self.download_findings, "portal"),
            ("GET", re.compile(r"^/portal/(?P<client_id>[\\w-]+)/engagements/(?P<engagement_id>[\\w-]+)/findings.csv$"),
             self.download_findings, "portal"),
        ])

    def download_findings(self, auth: AuthState, form: dict[str, str],
                          client_id: str, engagement_id: str | None = None) -> Response:
        # Inherited dispatch has authenticated the session and enforced portal access.
        if auth.context is None:
            return Response("Sign-in required.", status="403 Forbidden")
        try:
            output = render_client_findings_csv(
                self.store, auth.context, client_id, engagement_id=engagement_id)
        except TenantIsolationError:
            return Response("Export denied.", status="403 Forbidden")
        except (ValueError, KeyError, sqlite3.DatabaseError):
            return Response("Export unavailable.", status="400 Bad Request")
        return Response(
            output, content_type="text/csv; charset=utf-8",
            extra_headers=[("Content-Disposition", 'attachment; filename="LightUp-findings.csv"')])

    def portal(self, auth: AuthState, form: dict[str, str], client_id: str) -> Response:
        response = super().portal(auth, form, client_id)
        href = html.escape(f"/portal/{client_id}/findings.csv", quote=True)
        body = response.body.decode("utf-8").replace(
            "<h2>Findings</h2>",
            f'<div class="row"><h2>Findings</h2><a href="{href}">Download CSV</a></div>',
            1,
        )
        return Response(body, status=response.status)


def create_app_with_exports(store: DomainStore,
                            security: WebSecurity | None = None) -> FindingExportWebApp:
    return FindingExportWebApp(store, security)
