"""Opt-in Gunicorn/WSGI factory for constant, private HTTP 400 responses.

This module is deliberately not imported by the default production factory
or installed in the deployed Gunicorn command. Selection must be explicit.
The original factory retains all origin, trusted-proxy and DB validation.
"""

from __future__ import annotations

from .opaque_error_wsgi_optin import OpaqueErrorWSGI
from .production import create_production_app


def create_opaque_production_app(environ=None) -> OpaqueErrorWSGI:
    """Build the validated production shell with an outbound 400 privacy gate.

    Only synthetic offline labs are validated. The default production factory
    is unchanged and no authorization, scanning or test capability is added.
    """
    return OpaqueErrorWSGI(create_production_app(environ))
