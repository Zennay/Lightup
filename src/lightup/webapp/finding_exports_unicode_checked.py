"""Opt-in WSGI integration of the bounded tenant-checked finding CSV renderer.

This app factory is NOT the default web/CLI entrypoint. It reuses existing
session authentication, portal route admission and response security headers
from FindingExportWebApp. It makes no active target calls, authorization grants,
retest claims or database writes. Independent installed ingress and privacy
review remain mandatory before any production enablement.
"""
from __future__ import annotations

import sqlite3

from ..domain import DomainStore, TenantIsolationError
from ..finding_export_tenant_checked import render_tenant_findings_csv_checked
from .app import AuthState, Response
from .finding_exports import FindingExportWebApp
from .security import WebSecurity


class CheckedFindingExportWebApp(FindingExportWebApp):
    """Existing authorized GET routes, opt-in checked output instead of legacy."""

    def download_findings(
        self,
        auth: AuthState,
        form: dict[str, str],
        client_id: str,
        engagement_id: str | None = None,
    ) -> Response:
        # The parent WSGI dispatcher must authenticate the session and enforce
        # portal membership before entering this handler. Still fail closed if
        # called directly without a context; never manufacture an identity.
        if type(auth) is not AuthState or auth.context is None:
            return Response("Sign-in required.", status="403 Forbidden")
        try:
            output = render_tenant_findings_csv_checked(
                self.store, auth.context, client_id, engagement_id=engagement_id
            )
        except TenantIsolationError:
            return Response("Export denied.", status="403 Forbidden")
        except (ValueError, KeyError, sqlite3.DatabaseError):
            return Response("Export unavailable.", status="400 Bad Request")

        return Response(
            output,
            content_type="text/csv; charset=utf-8",
            extra_headers=[(
                "Content-Disposition",
                'attachment; filename="LightUp-findings.csv"',
            )],
        )


def create_app_with_checked_exports(
    store: DomainStore,
    security: WebSecurity | None = None,
) -> CheckedFindingExportWebApp:
    """Construct an explicitly opted-in app; never selected automatically."""
    return CheckedFindingExportWebApp(store, security)
