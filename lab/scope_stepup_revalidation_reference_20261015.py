"""Non-authorizing, in-memory race reference for issue #1173.

Never wired into LightUp dispatch. No grant issuance, handler, I/O or network.
A REVIEW_ONLY result explicitly is NOT permission to execute anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
    started_at: datetime

    def is_synthetic(self) -> bool:
        return (
            type(self) is ReviewRequest
            and all(_synthetic(getattr(self, k)) for k in
                    ("run", "client", "engagement", "asset", "tool", "capability"))
            and type(self.risk) is int and self.risk == 5
            and _aware(self.started_at)
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
            and self.issued_at < self.request.started_at < self.expires_at
            # Independent per-target destructive opt-in must expire within
            # 24 hours, never be minted after the fictional run began.
            and self.expires_at - self.issued_at <= timedelta(hours=24)
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
        # Treat a poisoned or user-constructed receipt as HOLD, never echo a
        # caller-provided status/reason/identifier. No flag is an authority.
        names = (
            "status", "reason", "authorization_verified", "permit_issued",
            "execution_enabled", "dispatch_allowed", "merge_approved",
            "release_approved",
        )
        # Inspect actual instance storage. Plain attribute reads can fall
        # back to dataclass class defaults after __delattr__, falsely passing
        # the six-false test on an incomplete/forged receipt.
        try:
            values = vars(self) if type(self) is ReviewReceipt else {}
            valid = (
                type(self) is ReviewReceipt
                and set(values) == set(names)
                and all(
                    type(values[name]) is bool and values[name] is False
                    for name in names[2:]
                )
                and type(values["status"]) is str
                and type(values["reason"]) is str
                and (
                    (values["status"] == "HOLD"
                     and values["reason"] == "not_verified")
                    or (values["status"] == "REVIEW_ONLY"
                        and values["reason"] == "synthetic_snapshot_consistent")
                )
            )
        except (AttributeError, KeyError, TypeError):
            valid = False
        status = values["status"] if valid else "HOLD"
        reason = values["reason"] if valid else "not_verified"
        return {
            "status": status,
            "reason": reason,
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "dispatch_allowed": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _hold() -> ReviewReceipt:
    # Fresh value each time: callers cannot poison a shared global singleton
    # and silently change future HOLD receipts via object.__setattr__.
    return ReviewReceipt("HOLD", "not_verified")


def _review() -> ReviewReceipt:
    return ReviewReceipt("REVIEW_ONLY", "synthetic_snapshot_consistent")


class OfflineRevalidationFence:
    """A race oracle, NOT an execution gate.

    The post-callback lock covers the final immutable comparison and an
    in-memory counter only. It explicitly does NOT guard any real handler.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._epoch = 0
        # Revocation is terminal for this disposable run reviewer. Reissuing
        # a "new" approval requires a fresh reviewer and a fresh run.
        self._closed = False
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
    def _time_fields(value: datetime) -> tuple[object, ...]:
        # datetime equality normalizes aware instants and ignores fold in
        # some same-tz cases. Review seals pin original representation too.
        return (
            value.year, value.month, value.day, value.hour, value.minute,
            value.second, value.microsecond, value.fold, value.utcoffset(),
        )

    @classmethod
    def _request_fields(cls, value: ReviewRequest) -> tuple[object, ...]:
        return (
            value.run, value.client, value.engagement, value.asset,
            value.tool, value.capability, value.risk,
            cls._time_fields(value.started_at),
        )

    @classmethod
    def _approval_fields(cls, value: ReferenceApproval) -> tuple[object, ...]:
        return (
            *cls._request_fields(value.request),
            cls._time_fields(value.issued_at),
            cls._time_fields(value.expires_at),
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
        # Snapshot exact caller fields on both sides of the copy. A caller
        # can mutate even frozen dataclasses in-process via object.__setattr__;
        # never store a mixed-time, split-identity or malformed reference.
        before_approval = self._approval_fields(approval)
        before_tool = self._tool_fields(tool)
        request = ReviewRequest(**{
            name: getattr(approval.request, name)
            for name in ReviewRequest.__dataclass_fields__
        })
        frozen = ReferenceApproval(request, approval.issued_at, approval.expires_at)
        snapshot = ToolSnapshot(tool.tool, tool.capability, tool.risk)
        with self._lock:
            if self._closed:
                raise ValueError("revoked review instance cannot be reopened")
            if (
                not frozen.is_well_formed()
                or not snapshot.is_well_formed()
                or self._approval_fields(frozen) != before_approval
                or self._tool_fields(snapshot) != before_tool
                or self._approval_fields(approval) != before_approval
                or self._tool_fields(tool) != before_tool
            ):
                raise ValueError("synthetic approval/registry changed during intake")
            self._approval = frozen
            self._tool = snapshot
            self._approval_seal = self._approval_fields(frozen)
            self._tool_seal = self._tool_fields(snapshot)
            self._epoch += 1

    def revoke(self) -> None:
        with self._lock:
            self._closed = True
            self._approval = None
            self._approval_seal = None
            # Discard both halves of the obsolete identity; leave no stale
            # synthetic capability registered on a permanently closed fence.
            self._tool = None
            self._tool_seal = None
            self._epoch += 1

    def replace_synthetic_tool(self, tool: ToolSnapshot) -> None:
        if type(tool) is not ToolSnapshot or not tool.is_well_formed():
            raise ValueError("invalid synthetic tool")
        original = self._tool_fields(tool)
        with self._lock:
            if self._closed:
                raise ValueError("revoked review instance cannot replace tools")
            snapshot = ToolSnapshot(tool.tool, tool.capability, tool.risk)
            if (
                not snapshot.is_well_formed()
                or self._tool_fields(snapshot) != original
                or self._tool_fields(tool) != original
            ):
                raise ValueError("synthetic tool changed during registry intake")
            self._tool = snapshot
            self._tool_seal = self._tool_fields(snapshot)
            self._epoch += 1

    def review(
        self,
        request: ReviewRequest,
        now: datetime,
        *,
        isolation_probe: Callable[[], object] | None = None,
        fresh_clock_probe: Callable[[], object] | None = None,
    ) -> ReviewReceipt:
        if (type(request) is not ReviewRequest or not request.is_synthetic()
                or not _aware(now)
                or isolation_probe is None or not callable(isolation_probe)
                or (fresh_clock_probe is not None
                    and not callable(fresh_clock_probe))):
            return _hold()

        # Hold a private immutable copy of every caller-controlled field.
        # A callback that rewrites a frozen dataclass with object.__setattr__
        # must not silently replace the reviewed identity after validation.
        initial_request = ReviewRequest(**{
            name: getattr(request, name)
            for name in ReviewRequest.__dataclass_fields__
        })
        original_fields = self._request_fields(initial_request)
        if self._request_fields(request) != original_fields:
            return _hold()

        # The expensive, untrusted verifier deliberately executes OUTSIDE the
        # lock; changes while it runs must invalidate the captured epoch.
        with self._lock:
            # A revoked reviewer cannot call any untrusted verifier again.
            if self._closed:
                return _hold()
            epoch = self._epoch
        try:
            if isolation_probe() is not True:
                return _hold()
            # Optional second synthetic clock observation can prove that an
            # isolation callback did not outlive the original approval window.
            # Never execute clock callbacks under the ledger lock.
            fresh_now = now if fresh_clock_probe is None else fresh_clock_probe()
        except Exception:
            return _hold()
        if not _aware(fresh_now) or fresh_now < now:
            return _hold()

        with self._lock:
            approval, tool = self._approval, self._tool
            if (self._closed or epoch != self._epoch
                    or approval is None or tool is None):
                return _hold()
            if not approval.is_well_formed() or not tool.is_well_formed():
                return _hold()
            if (self._approval_fields(approval) != self._approval_seal
                    or self._tool_fields(tool) != self._tool_seal):
                return _hold()
            if (self._request_fields(request) != original_fields
                    or self._request_fields(approval.request) != original_fields
                    or tool.tool != initial_request.tool
                    or tool.capability != initial_request.capability
                    or tool.risk != initial_request.risk
                    or fresh_now < initial_request.started_at
                    or fresh_now < approval.issued_at
                    or fresh_now >= approval.expires_at):
                return _hold()
            self._review_count += 1
            # Never emit an authorization or execution permit.
            return _review()
