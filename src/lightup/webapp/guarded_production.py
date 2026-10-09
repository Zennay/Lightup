"""Opt-in WSGI production factory with canonical request-path admission.

This is deliberately a separate Gunicorn target rather than a silent change
to the deployed production factory, source owners or runtime service.
The deployment operator must explicitly choose this factory after approval.
"""
from __future__ import annotations

from .pathinfo_guard import CanonicalPathInfoGuard
from .production import create_production_app


def create_guarded_production_app(environ=None) -> CanonicalPathInfoGuard:
    """Preserve the existing production config/HTTPS validation, adding a
    fail-closed outer WSGI path guard before the underlying web application.
    """
    app = create_production_app(environ)
    return CanonicalPathInfoGuard(app, production=True)
