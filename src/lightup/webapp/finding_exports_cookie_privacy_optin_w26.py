"""Extra opt-in session-cookie disclosure gate for the checked CSV web factory.

Only handles an already-rendered, already-authorized CSV response from the
separate W23 opt-in checked web application. This deny-only presentation
boundary is not installed by the default LightUp web or CLI entrypoint.
It does not guarantee removal of arbitrary secrets or live ingress safety.
"""
from __future__ import annotations

import re
import unicodedata

from ..domain import DomainStore
from .app import AuthState, Response
from .finding_exports_unicode_checked import CheckedFindingExportWebApp
from .security import WebSecurity

# Exact app session-cookie name, not a blanket 'token' / personal-data
# classifier. Compatibility-normalize ONLY a private inspection copy, never
# the caller's persisted findings or the CSV that is actually returned.
_SESSION_COOKIE_VALUE = re.compile(
    r"(?<![\w])lightup_session\s*=\s*[^\s;\r\n,\"]+",
    flags=re.IGNORECASE,
)


class CookiePrivacyCheckedFindingExportWebApp(CheckedFindingExportWebApp):
    """Uninstalled post-render deny gate for one known cookie disclosure."""

    def download_findings(
        self,
        auth: AuthState,
        form: dict[str, str],
        client_id: str,
        engagement_id: str | None = None,
    ) -> Response:
        response = super().download_findings(
            auth, form, client_id, engagement_id=engagement_id
        )
        if response.status != "200 OK":
            return response

        # The inherited renderer only emits bounded UTF-8 text. Any unknown
        # response shape still fails closed before WSGI releases response bytes.
        try:
            if type(response.body) is not bytes:
                raise ValueError("unexpected body")
            probe = unicodedata.normalize("NFKC", response.body.decode("utf-8"))
        except (UnicodeError, ValueError, TypeError):
            return Response("Export unavailable.", status="400 Bad Request")

        if _SESSION_COOKIE_VALUE.search(probe):
            return Response("Export unavailable.", status="400 Bad Request")
        return response


def create_app_with_checked_cookie_privacy(
    store: DomainStore, security: WebSecurity | None = None
) -> CookiePrivacyCheckedFindingExportWebApp:
    """Explicit opt-in only; the production factory remains unchanged."""
    return CookiePrivacyCheckedFindingExportWebApp(store, security)
