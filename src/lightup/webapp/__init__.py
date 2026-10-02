"""Minimal standalone web shell for LightUp (stdlib WSGI, no dependencies)."""

from .app import LightUpWebApp, create_app

__all__ = ["LightUpWebApp", "create_app"]
