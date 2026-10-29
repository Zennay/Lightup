"""Gunicorn factory. Production never falls back to development settings."""
import os
from pathlib import Path

from ..domain import DomainStore
from .app import create_app
from .security import WebSecurity
from .session_cookie_guard import CookieEnvelopeGuard


def create_production_app(environ=None):
    env = os.environ if environ is None else environ
    public_origin = env.get("LIGHTUP_PUBLIC_ORIGIN")
    db = env.get("LIGHTUP_DB")
    if not public_origin or not db or not Path(db).is_absolute():
        raise ValueError("LIGHTUP_PUBLIC_ORIGIN and an absolute LIGHTUP_DB are required")
    security = WebSecurity(public_origin, env.get("LIGHTUP_TRUSTED_PROXY_IP", "127.0.0.1"))
    # Validate one unambiguous session credential before form body reads,
    # authentication, CSRF handling or domain state access.
    return CookieEnvelopeGuard(create_app(DomainStore(db), security), production=True)
