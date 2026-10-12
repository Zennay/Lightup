"""Opt-in, deny-only offline validation for legacy public scope configuration.

This is not wired into ScopePolicy.decide, ToolExecutor or any ingress.
Returning normally indicates only syntactic consistency, NEVER consent.
No DNS, networking, persisted grants, or target interactions are performed.
See docs/scope-297-atomic-config-reference-20261012.md.
"""
from __future__ import annotations

import re
from ipaddress import ip_network

from .scope import ScopePolicy


class InvalidPublicScopeConfiguration(ValueError):
    """A proposed public-scope configuration is noncanonical or ambiguous."""


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)


def validate_public_scope_configuration(policy: ScopePolicy) -> None:
    """Refuse malformed configuration *before* any path-specific target decision.

    Success is only a shape check: it cannot issue, validate or prolong a
    real authorization grant. In particular, call sites must still enforce
    binding to the real issuer, tenant, asset, capability and active window.
    """
    if type(policy) is not ScopePolicy:
        raise InvalidPublicScopeConfiguration("scope policy must be exact ScopePolicy")
    if type(policy.allow_private_lab) is not bool:
        raise InvalidPublicScopeConfiguration("private-lab switch must be bool")
    if type(policy.require_authorization_for_public) is not bool:
        raise InvalidPublicScopeConfiguration("public authorization switch must be bool")
    if not policy.require_authorization_for_public:
        raise InvalidPublicScopeConfiguration("public authorization cannot be disabled")
    if type(policy.explicit_hosts) is not frozenset:
        raise InvalidPublicScopeConfiguration("explicit hosts must be a frozenset")
    if type(policy.explicit_networks) is not tuple:
        raise InvalidPublicScopeConfiguration("explicit networks must be a tuple")

    for host in policy.explicit_hosts:
        if type(host) is not str or not host or len(host) > 253 or not host.isascii():
            raise InvalidPublicScopeConfiguration("invalid explicit host identity")
        if host != host.strip() or host != host.lower() or host.endswith("."):
            raise InvalidPublicScopeConfiguration("noncanonical explicit host identity")
        if any(_LABEL.fullmatch(label) is None for label in host.split(".")):
            raise InvalidPublicScopeConfiguration("invalid explicit hostname label")

    for network in policy.explicit_networks:
        if type(network) is not str or not network or network != network.strip():
            raise InvalidPublicScopeConfiguration("invalid explicit network identity")
        try:
            parsed = ip_network(network, strict=True)
        except (ValueError, TypeError) as exc:
            raise InvalidPublicScopeConfiguration("malformed explicit network") from exc
        if network != str(parsed):
            raise InvalidPublicScopeConfiguration("noncanonical explicit network")
