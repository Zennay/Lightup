from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from .models import Authorization, Target


class ScopeReason(str, Enum):
    LOOPBACK = "loopback"
    PRIVATE_LAB = "private_lab"
    EXPLICIT_HOST = "explicit_host"
    EXPLICIT_NETWORK = "explicit_network"
    AUTHORIZATION_MISSING = "authorization_missing"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    OUT_OF_SCOPE = "out_of_scope"
    INVALID_TARGET = "invalid_target"


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    normalized_host: str | None
    reason: ScopeReason


# These are exact, deliberately bounded lab address sets. Python's generic
# is_private includes some reserved/special-use ranges not authorized as labs.
_LAB_NETWORKS = tuple(
    ip_network(value) for value in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "fc00::/7", "fe80::/10",
    )
)


def _canonical_policy_host(value: str) -> str:
    if (
        type(value) is not str or not value
        or value != value.strip()
        or "://" in value or any(char in value for char in "/\\@%?#")
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        raise ValueError("explicit host must be a plain host identity")
    if value.endswith("..") or ".." in value or value.startswith("."):
        raise ValueError("invalid explicit host dot boundary")
    host = value.removesuffix(".").lower()
    if not host:
        raise ValueError("explicit host cannot be empty")
    return host


@dataclass(frozen=True)
class ScopePolicy:
    allow_private_lab: bool = True
    explicit_hosts: frozenset[str] = frozenset()
    explicit_networks: tuple[str, ...] = ()
    require_authorization_for_public: bool = True

    def __post_init__(self) -> None:
        # Validate the WHOLE policy before any localhost/hostname decision:
        # malformed networks cannot be ignored just because the target is DNS.
        if (
            type(self.allow_private_lab) is not bool
            or type(self.require_authorization_for_public) is not bool
        ):
            raise ValueError("scope policy switches must be exact booleans")
        if type(self.explicit_hosts) not in (frozenset, set):
            raise ValueError("explicit hosts must be a builtin set")
        if type(self.explicit_networks) not in (tuple, list):
            raise ValueError("explicit networks must be a builtin list or tuple")

        normalized_hosts = frozenset(
            _canonical_policy_host(host) for host in self.explicit_hosts
        )
        entries = tuple(self.explicit_networks)
        for entry in entries:
            if (
                type(entry) is not str or not entry.strip()
                or entry != entry.strip()
                or "%" in entry
            ):
                raise ValueError("explicit network must be an exact CIDR string")
            ip_network(entry, strict=False)  # raises on malformed CIDR

        # Frozen fields alone do not protect caller-owned lists/sets.
        object.__setattr__(self, "explicit_hosts", normalized_hosts)
        object.__setattr__(self, "explicit_networks", entries)

    def _networks(self):
        return tuple(ip_network(item, strict=False) for item in self.explicit_networks)

    @staticmethod
    def normalize_host(value: str) -> str | None:
        if type(value) is not str:
            return None
        raw = value.strip()
        if not raw or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            return None
        # Bare IPv6 without brackets was formerly truncated by urlparse.
        # Reject rather than returning a shorter (possibly trusted) identity.
        if "://" not in raw and not raw.startswith("[") and raw.count(":") > 1:
            return None
        try:
            parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
            if parsed.username is not None or parsed.password is not None:
                return None
            host = parsed.hostname
        except ValueError:
            return None
        if not host or "%" in host or "\\" in host:
            return None
        if host.endswith("..") or ".." in host or host.startswith("."):
            return None
        return host.removesuffix(".").lower() or None

    def decide(self, target: Target) -> ScopeDecision:
        if type(target) is not Target:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        host = self.normalize_host(target.value)
        if host is None:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)

        if host == "localhost":
            return ScopeDecision(True, host, ScopeReason.LOOPBACK)

        try:
            addr = ip_address(host)
        except ValueError:
            addr = None

        if addr is not None:
            if addr.is_loopback:
                return ScopeDecision(True, host, ScopeReason.LOOPBACK)
            if self.allow_private_lab and any(
                addr in network for network in _LAB_NETWORKS
                if addr.version == network.version
            ):
                return ScopeDecision(True, host, ScopeReason.PRIVATE_LAB)
            if any(
                addr in network for network in self._networks()
                if addr.version == network.version
            ):
                if self.require_authorization_for_public:
                    if target.authorization is None:
                        return ScopeDecision(False, host, ScopeReason.AUTHORIZATION_MISSING)
                    if not _current_literal_authorization(target.authorization):
                        return ScopeDecision(False, host, ScopeReason.AUTHORIZATION_EXPIRED)
                return ScopeDecision(True, host, ScopeReason.EXPLICIT_NETWORK)
            return ScopeDecision(False, host, ScopeReason.OUT_OF_SCOPE)

        if host in self.explicit_hosts:
            if self.require_authorization_for_public:
                if target.authorization is None:
                    return ScopeDecision(False, host, ScopeReason.AUTHORIZATION_MISSING)
                if not _current_literal_authorization(target.authorization):
                    return ScopeDecision(False, host, ScopeReason.AUTHORIZATION_EXPIRED)
            return ScopeDecision(True, host, ScopeReason.EXPLICIT_HOST)

        return ScopeDecision(False, host, ScopeReason.OUT_OF_SCOPE)


def _current_literal_authorization(authorization: object) -> bool:
    # A legacy dataclass annotation is NOT a grant type/runtime check.
    # Never invoke a caller-supplied is_current() method.
    if type(authorization) is not Authorization:
        return False
    if any(
        type(value) is not str or not value.strip()
        for value in (authorization.owner, authorization.reference)
    ):
        return False
    start, end = authorization.valid_from, authorization.valid_until
    for bound in (start, end):
        if bound is not None and (
            type(bound) is not datetime
            or type(bound.tzinfo) is not timezone
            or bound.utcoffset() is None
        ):
            return False
    if start is not None and end is not None and start > end:
        return False
    instant = datetime.now(timezone.utc)
    return (
        (start is None or start <= instant)
        and (end is None or instant <= end)
    )
