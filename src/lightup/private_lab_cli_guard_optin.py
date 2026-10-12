"""Uninstalled #905 reference guard for the private-lab CLI policy switch.

The real CLI source belongs to PR #100. This function does not replace
lightup.cli._policy, does not modify the command parser and is NOT wired into
the command path. It is an isolated exact-type contract for source owner review.
"""
from __future__ import annotations

import argparse

from .cli import _policy
from .scope import ScopePolicy


def checked_private_lab_cli_policy(args: argparse.Namespace) -> ScopePolicy:
    """Reject non-boolean lab markers *before* invoking legacy policy logic."""
    if type(args) is not argparse.Namespace:
        raise ValueError("CLI policy requires canonical argument namespace")
    params = vars(args)
    if "allow_private_lab" not in params or type(params["allow_private_lab"]) is not bool:
        raise ValueError("CLI private-lab policy requires explicit boolean")
    return _policy(args)
