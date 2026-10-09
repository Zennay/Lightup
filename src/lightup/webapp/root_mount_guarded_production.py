"""Opt-in root-mount guarded production factory; does not change Gunicorn entrypoint.

The currently deployed production.create_production_app remains the default.
An explicit source-owner review must compose this boundary with the other
independently owned pre-auth ingress guards before a deployment.
"""
from __future__ import annotations

from .production import create_production_app
from .root_mount_guard import RootMountGuard


def create_root_mount_guarded_production_app(environ=None) -> RootMountGuard:
    """Construct the real, configured production app with a strict root mount."""
    return RootMountGuard(create_production_app(environ), production=True)
