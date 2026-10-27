"""Gunicorn factory. Production never falls back to development settings."""
import os
from pathlib import Path

from ..domain import DomainStore
from .finding_exports import create_app_with_exports as create_app
from .security import WebSecurity


def create_production_app(environ=None):
    env = os.environ if environ is None else environ
    public_origin = env.get("LIGHTUP_PUBLIC_ORIGIN")
    db = env.get("LIGHTUP_DB")
    if not public_origin or not db or not Path(db).is_absolute():
        raise ValueError("LIGHTUP_PUBLIC_ORIGIN and an absolute LIGHTUP_DB are required")
    security = WebSecurity(public_origin, env.get("LIGHTUP_TRUSTED_PROXY_IP", "127.0.0.1"))
    return create_app(DomainStore(db), security)
