"""Strict, opt-in lexical target identity gate for the existing ScopePolicy.

No DNS lookup, port connection, network adapter, permit issuance or active
testing. Existing ScopePolicy and ActivationGate remain untouched by default.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit

from .models import Target
from .scope import ScopeDecision, ScopePolicy, ScopeReason

_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ALLOWED_SCHEMES = frozenset(("http", "https"))
_MAX_RAW_LENGTH = 2048


def _canonical_target_host(value: str) -> str | None:
    """Parse a narrowly permitted target authority without URL rewrites.

    Unlike urllib.parse, this gate checks the original bytes/characters first:
    urlsplit may silently delete CR/LF/TAB from hostnames. An allowlist match
    after such deletion would be a different identity from the submitted input.
    """
    if type(value) is not str or not value or len(value) > _MAX_RAW_LENGTH:
        return None
    if value != value.strip() or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return None
    if "\\" in value or value.startswith("//"):
        return None

    # A full, unbracketed IPv6 literal is valid as a raw host; urllib's
    # authority parser cannot distinguish its colons from a TCP port.
    try:
        addr = ip_address(value)
    except ValueError:
        pass
    else:
        # Legacy ScopePolicy parses bare ::1 as a non-host; never widen it.
        # Explicitly bracket IPv6 so URL authority parsing is unambiguous.
        if addr.version == 6:
            return None
        return str(addr).lower()

    is_url = "://" in value
    try:
        if is_url:
            parsed = urlsplit(value)
            if parsed.scheme not in _ALLOWED_SCHEMES or not parsed.netloc:
                return None
        else:
            # Disallow other scheme-like or slash-prefixed authorities.
            if value.startswith("/") or "?" in value or "#" in value:
                return None
            parsed = urlsplit("//" + value)
            if parsed.path or parsed.query or parsed.fragment:
                return None
        netloc = parsed.netloc
        if not netloc or any(ch in netloc for ch in ("@", "%", "\\", ",")):
            return None
        if not netloc.isascii() or netloc.endswith(":"):
            return None
        # urlsplit().hostname may silently ignore junk after closing IPv6
        # brackets: reject rather than grant a permit on a different identity.
        if netloc.startswith("["):
            if not re.fullmatch(r"\[[0-9A-Fa-f:.]+\](?::[0-9]{1,5})?", netloc):
                return None
        elif not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", netloc):
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.fragment:
            return None
        host = parsed.hostname
        if not host or any(ord(ch) < 33 or ord(ch) > 126 for ch in host):
            return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
    except (ValueError, UnicodeError):
        return None

    # An unbracketed IPv6 literal with a scheme/port cannot be an authority;
    # urlsplit() itself rejects its invalid port/bracket representation.
    try:
        ip = ip_address(host)
    except ValueError:
        if ":" in host:
            return None
        canonical = host.lower().rstrip(".")
        if len(canonical) > 253 or not canonical:
            return None
        if not all(_HOST_LABEL.fullmatch(part) for part in canonical.split(".")):
            return None
        return canonical
    else:
        # Existing ScopePolicy only recognizes bracketed IPv6 authorities.
        return f"[{ip}]" if ip.version == 6 else str(ip).lower()


@dataclass(frozen=True)
class StrictTargetScopePolicy:
    """Use explicit strict target syntax before delegating *all* permissions.

    Can be supplied to ActivationGate as an opt-in scope-policy object. It
    never issues its own permissions; the existing ScopePolicy still decides
    loopback, lab, public authorization, expiry and explicit allowlists.
    """
    base: ScopePolicy

    def __post_init__(self):
        if type(self.base) is not ScopePolicy:
            raise TypeError("strict scope requires exact existing ScopePolicy")

    def decide(self, target: Target) -> ScopeDecision:
        if type(target) is not Target:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        normalized = _canonical_target_host(target.value)
        if normalized is None:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        return self.base.decide(Target(
            value=normalized,
            authorization=target.authorization,
            labels=target.labels,
        ))
