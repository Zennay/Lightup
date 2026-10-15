"""Issue #294: opt-in *non-authorizing* snapshot of untrusted scope collections.

This standalone reference is not plugged into ScopePolicy, the grant store, or
the target-active executor. REVIEW_ONLY means shape review *only*, never scope,
asset permission, a live authorization, a scan permit, or human release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network
from unicodedata import category

from .scope import ScopePolicy


_MAX_ITEMS = 128
_MAX_HOST_LENGTH = 253
_MAX_NETWORK_LENGTH = 64
_RELEASE_FIELDS = (
    "authorization_verified",
    "permit_issued",
    "execution_enabled",
    "scan_approved",
    "merge_approved",
    "release_approved",
)


@dataclass(frozen=True, slots=True)
class ScopeCollectionReview:
    """A local shape snapshot; its truth value is *never* authorization."""

    status: str
    reason: str
    _hosts: frozenset[str] = field(default_factory=frozenset, repr=False)
    _networks: tuple[str, ...] = field(default_factory=tuple, repr=False)

    def __bool__(self) -> bool:
        return False

    @property
    def authorization_verified(self) -> bool:
        return False

    @property
    def permit_issued(self) -> bool:
        return False

    @property
    def execution_enabled(self) -> bool:
        return False

    @property
    def scan_approved(self) -> bool:
        return False

    @property
    def merge_approved(self) -> bool:
        return False

    @property
    def release_approved(self) -> bool:
        return False

    def to_public_dict(self) -> dict[str, str | bool]:
        """Privacy-minimal receipt: never leak customer or target input."""
        if type(self) is not ScopeCollectionReview:
            return _deny("invalid_receipt").to_public_dict()
        status = self.status
        reason = self.reason
        if type(status) is not str or type(reason) is not str:
            status, reason = "HOLD", "invalid_receipt"
        elif (status, reason) not in (
            ("HOLD", "invalid_collections"),
            ("HOLD", "invalid_policy"),
            ("HOLD", "invalid_receipt"),
            ("REVIEW_ONLY", "canonical_collections"),
        ):
            status, reason = "HOLD", "invalid_receipt"
        return {"status": status, "reason": reason,
                **{name: False for name in _RELEASE_FIELDS}}


def _deny(reason: str) -> ScopeCollectionReview:
    return ScopeCollectionReview("HOLD", reason)


def _lexical_host_metadata_identity(value: object) -> bool:
    """A deliberately narrow host *shape*, not DNS or IDNA authorization.

    Do not parse URLs, normalize aliases, resolve names, issue grants or
    silently turn userinfo/ports/paths/Unicode control marks into hosts.
    Exact IDN spellings survive unchanged for source-owner review.
    """
    if type(value) is not str or not 0 < len(value) <= _MAX_HOST_LENGTH:
        return False
    labels = value.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not label[0].isalnum() or not label[-1].isalnum():
            return False
        for char in label:
            if not (char.isalnum() or char == "-" or category(char).startswith("M")):
                return False
    return True


def _bounded_hosts(raw: object) -> frozenset[str] | None:
    if type(raw) not in (set, frozenset, tuple, list):
        return None
    if len(raw) > _MAX_ITEMS:
        return None
    try:
        copied = tuple(raw)
    except RuntimeError:
        return None
    if not all(_lexical_host_metadata_identity(item) for item in copied):
        return None
    # A list/tuple pretending to represent an identity set must not silently
    # discard repeated entries. Malformed input is HOLD, not a normalized
    # REVIEW_ONLY receipt. Actual set/frozenset objects are unique by design.
    if len(frozenset(copied)) != len(copied):
        return None
    return frozenset(copied)


def _bounded_networks(raw: object) -> tuple[str, ...] | None:
    if type(raw) not in (tuple, list) or len(raw) > _MAX_ITEMS:
        return None
    try:
        copied = tuple(raw)
    except RuntimeError:
        return None
    for value in copied:
        if type(value) is not str or not 0 < len(value) <= _MAX_NETWORK_LENGTH:
            return None
        try:
            parsed = ip_network(value, strict=True)
        except ValueError:
            return None
        # A review must not quietly mint an expanded CIDR, normalize host
        # bits, abbreviate a bare IP to /32 or /128, or rewrite IPv6 spellings.
        # Exact on-wire network identity is deliberately stricter than the
        # legacy installed ScopePolicy parser (which remains source-owned).
        if str(parsed) != value:
            return None
    return copied


def snapshot_untrusted_scope_collections(
    hosts: object, networks: object,
) -> ScopeCollectionReview:
    """Copy only exact built-in containers/strings into independent snapshots.

    No conversion to ScopePolicy, and no authorization or network I/O.
    A structurally canonical result is still strictly REVIEW_ONLY.
    """
    safe_hosts = _bounded_hosts(hosts)
    safe_networks = _bounded_networks(networks)
    if safe_hosts is None or safe_networks is None:
        return _deny("invalid_collections")
    return ScopeCollectionReview(
        "REVIEW_ONLY", "canonical_collections", safe_hosts, safe_networks
    )


def inspect_existing_scope_policy(policy: object) -> ScopeCollectionReview:
    """Conservatively HOLD a policy retaining caller-owned mutable collections.

    This is an offline diagnostic. It does not change installed decisions.
    """
    if type(policy) is not ScopePolicy:
        return _deny("invalid_policy")
    if type(policy.allow_private_lab) is not bool:
        return _deny("invalid_policy")
    if type(policy.require_authorization_for_public) is not bool:
        return _deny("invalid_policy")
    if type(policy.explicit_hosts) is not frozenset:
        return _deny("invalid_policy")
    if type(policy.explicit_networks) is not tuple:
        return _deny("invalid_policy")
    snapshot = snapshot_untrusted_scope_collections(
        policy.explicit_hosts, policy.explicit_networks
    )
    if snapshot.status != "REVIEW_ONLY":
        return _deny("invalid_policy")
    return snapshot
