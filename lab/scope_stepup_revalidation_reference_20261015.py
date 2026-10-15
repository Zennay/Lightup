"""Non-authorizing, in-memory race reference for issue #1173.

Never wired into LightUp dispatch. No grant issuance, handler, I/O or network.
A REVIEW_ONLY result explicitly is NOT permission to execute anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from threading import Lock
from typing import Callable


_SYNTHETIC_ID = re.compile(r"lab-[a-z0-9_-]{1,60}\Z")


def _synthetic(value: object) -> bool:
    return type(value) is str and _SYNTHETIC_ID.fullmatch(value) is not None


def _aware(value: object) -> bool:
    # Only exact stdlib fixed-offset timezone objects; arbitrary tzinfo
    # callbacks must never execute while the ledger lock is held.
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        return False
    return value.utcoffset() is not None


@dataclass(frozen=True)
class ReviewRequest:
    run: str
    client: str
    engagement: str
    asset: str
    tool: str
    capability: str
    risk: int

    def is_synthetic(self) -> bool:
        return (
            type(self) is ReviewRequest
            and all(_synthetic(getattr(self, k)) for k in
                    ("run", "client", "engagement", "asset", "tool", "capability"))
            and type(self.risk) is int and self.risk == 5
        )


@dataclass(frozen=True)
class ReferenceApproval:
    request: ReviewRequest
    issued_at: datetime
    expires_at: datetime

    def is_well_formed(self) -> bool:
        return (
            type(self) is ReferenceApproval
            and type(self.request) is ReviewRequest
            and self.request.is_synthetic()
            and _aware(self.issued_at) and _aware(self.expires_at)
            and self.issued_at < self.expires_at
        )


@dataclass(frozen=True)
class ToolSnapshot:
    tool: str
    capability: str
    risk: int

    def is_well_formed(self) -> bool:
        return (
            type(self) is ToolSnapshot
            and _synthetic(self.tool) and _synthetic(self.capability)
            and type(self.risk) is int and self.risk == 5
        )


@dataclass(frozen=True)
class ReviewReceipt:
    status: str
    reason: str
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    dispatch_allowed: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "status": self.status,
            "reason": self.reason,
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "dispatch_allowed": False,
            "merge_approved": False,
            "release_approved": False,
        }


_HOLD = ReviewReceipt("HOLD", "not_verified")
_REVIEW = ReviewReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")


class OfflineRevalidationFence:
    """A race oracle, NOT an execution gate.

    The post-callback lock covers the final immutable comparison and an
    in-memory counter only. It explicitly does NOT guard any real handler.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._epoch = 0
        self._approval: ReferenceApproval | None = None
        self._tool: ToolSnapshot | None = None
        # Exact tuple seals detect changes to frozen dataclass internals via
        # object.__setattr__, which does not increment the normal epoch.
        # These are review-only canaries, not tamper-proof Python secrets.
        self._approval_seal: tuple[object, ...] | None = None
        self._tool_seal: tuple[object, ...] | None = None
        self._review_count = 0

    @property
    def review_count(self) -> int:
        with self._lock:
            return self._review_count

    @staticmethod
    def _approval_fields(value: ReferenceApproval) -> tuple[object, ...]:
        request = value.request
        return (
            request.run, request.client, request.engagement, request.asset,
            request.tool, request.capability, request.risk,
            value.issued_at, value.expires_at,
        )

    @staticmethod
    def _tool_fields(value: ToolSnapshot) -> tuple[object, ...]:
        return value.tool, value.capability, value.risk

    def replace_synthetic_reference(
        self, approval: ReferenceApproval, tool: ToolSnapshot
    ) -> None:
        if (type(approval) is not ReferenceApproval
                or not approval.is_well_formed()
                or type(tool) is not ToolSnapshot
                or not tool.is_well_formed()):
            raise ValueError("invalid synthetic reference")
        # Copy caller-owned objects, including the request, to avoid aliasing.
        request = ReviewRequest(**{
            name: getattr(approval.request, name)
            for name in ReviewRequest.__dataclass_fields__
        })
        frozen = ReferenceApproval(request, approval.issued_at, approval.expires_at)
        snapshot = ToolSnapshot(tool.tool, tool.capability, tool.risk)
        with self._lock:
            self._approval = frozen
            self._tool = snapshot
            self._approval_seal = self._approval_fields(frozen)
            self._tool_seal = self._tool_fields(snapshot)
            self._epoch += 1

    def revoke(self) -> None:
        with self._lock:
            self._approval = None
            self._approval_seal = None
            self._epoch += 1

    def replace_synthetic_tool(self, tool: ToolSnapshot) -> None:
        if type(tool) is not ToolSnapshot or not tool.is_well_formed():
            raise ValueError("invalid synthetic tool")
        with self._lock:
            self._tool = ToolSnapshot(tool.tool, tool.capability, tool.risk)
            self._tool_seal = self._tool_fields(self._tool)
            self._epoch += 1

    def review(
        self,
        request: ReviewRequest,
        now: datetime,
        *,
        isolation_probe: Callable[[], object] | None = None,
    ) -> ReviewReceipt:
        if (type(request) is not ReviewRequest or not request.is_synthetic()
                or not _aware(now)
                or isolation_probe is None or not callable(isolation_probe)):
            return _HOLD

        # Hold a private immutable copy of every caller-controlled field.
        # A callback that rewrites a frozen dataclass with object.__setattr__
        # must not silently replace the reviewed identity after validation.
        initial_request = ReviewRequest(**{
            name: getattr(request, name)
            for name in ReviewRequest.__dataclass_fields__
        })
        if request != initial_request:
            return _HOLD

        # The expensive, untrusted verifier deliberately executes OUTSIDE the
        # lock; changes while it runs must invalidate the captured epoch.
        with self._lock:
            epoch = self._epoch
        try:
            if isolation_probe() is not True:
                return _HOLD
        except Exception:
            return _HOLD

        with self._lock:
            approval, tool = self._approval, self._tool
            if epoch != self._epoch or approval is None or tool is None:
                return _HOLD
            if not approval.is_well_formed() or not tool.is_well_formed():
                return _HOLD
            if (self._approval_fields(approval) != self._approval_seal
                    or self._tool_fields(tool) != self._tool_seal):
                return _HOLD
            if (request != initial_request or approval.request != initial_request
                    or tool.tool != initial_request.tool
                    or tool.capability != initial_request.capability
                    or tool.risk != initial_request.risk
                    or now < approval.issued_at or now >= approval.expires_at):
                return _HOLD
            self._review_count += 1
            # Never emit an authorization or execution permit.
            return _REVIEW
