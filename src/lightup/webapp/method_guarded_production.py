"""Opt-in Gunicorn factory with exact WSGI method-token admission.

Not the deployed Gunicorn entrypoint. Promotion must be coordinated with the
production factory and canonical PATH_INFO guard owners to compose both layers.
"""
from __future__ import annotations

from .method_guard import CanonicalMethodGuard
from .production import create_production_app


def create_method_guarded_production_app(environ=None):
    """Fail closed on production config; then wrap the real production app."""
    return CanonicalMethodGuard(create_production_app(environ), production=True)
