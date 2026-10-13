"""Explicit opt-in synthetic-only offline preview CLI for issue #1307.

Usage: python -m lightup.offline_executor_batch_cli_optin --input plan.json

Never uses targets from input, credentials, grants, scanners or network.
Creates an isolated *temporary* SQLite run to exercise the real metadata
preview; does not invoke ToolExecutor.execute or any registered tool handler.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from .ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolExecutor, ToolOutput, ToolRegistry,
)
from .engagements import AssessmentMode, RiskLevel
from .execution_policy import InteractionKind
from .offline_executor_boundary_preview_optin import OfflineExecutorBoundaryPreview
from .state import StateStore


MAX_BYTES = 4096
_STATIC_ID = re.compile(r"offline-check-(?:00[1-9]|0[1-5][0-9]|06[0-4])\Z")
_GENERIC_ERROR = "synthetic offline preview denied"


class InvalidSyntheticPlan(ValueError):
    """No user content is included in any error message."""


def _deny() -> None:
    raise InvalidSyntheticPlan(_GENERIC_ERROR)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _deny()
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    _deny()


def _open_plan_fd_without_symlink_ancestors(path: str) -> int:
    """Pin each directory by descriptor, rejecting every symlink component.

    The cwd or filesystem can still be adversarial; this is only safe local
    input admission, not a secure filesystem namespace or production gate.
    """
    if type(path) is not str or not 1 <= len(path) <= 4096:
        _deny()
    required = ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY")
    if not all(hasattr(os, flag) for flag in required):
        _deny()
    # dir_fd support is exercised by os.open itself; platforms lacking it
    # raise and the CLI returns its one opaque error, never a weaker open.
    # pathlib collapses repeated separators and '.' only. Parent traversal
    # is explicitly forbidden to keep every directory lookup predictable.
    parts = Path(path).parts
    if not parts or len(parts) > 65 or ".." in parts:
        _deny()
    absolute = parts[0] in ("/", "//")
    names = parts[1:] if absolute else parts
    if not names or any(not name or len(name) > 255 for name in names):
        _deny()
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    file_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = os.open("/" if absolute else ".", directory_flags)
    try:
        for name in names[:-1]:
            next_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(names[-1], file_flags, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def _read_bounded_snapshot(fd: int) -> bytes:
    """Fully consume one <=4097 byte snapshot, including short OS reads."""
    chunks: list[bytes] = []
    remaining = MAX_BYTES + 1
    while remaining:
        part = os.read(fd, remaining)
        if not part:
            break
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def _load_plan(path: str) -> tuple[str, ...]:
    # Never block on a FIFO, follow final *or parent* symlinks, or open
    # an arbitrary device for reading. Every directory is pinned by dir_fd.
    fd = _open_plan_fd_without_symlink_ancestors(path)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > MAX_BYTES
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            # Hard-link aliases and group/world-writable files have mutable
            # external entry points even when path components are nofollow.
            _deny()
        # Check content twice through the same pinned descriptor, still
        # respecting the per-pass kernel budget. A stable fstat alone cannot
        # detect an in-place rewrite whose size/times were restored.
        raw = _read_bounded_snapshot(fd)
        if not raw or len(raw) > MAX_BYTES:
            _deny()
        os.lseek(fd, 0, os.SEEK_SET)
        if _read_bounded_snapshot(fd) != raw:
            _deny()
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size != before.st_size
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_mode != before.st_mode
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or after.st_nlink != before.st_nlink
            or after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            # Same-length changes often evade a size-only after-read check.
            # Metadata comparisons narrow that gap but do not establish an
            # atomic snapshot against hostile same-timestamp rewrites.
            _deny()
    finally:
        os.close(fd)
    if not raw or len(raw) > MAX_BYTES:
        _deny()
    try:
        plan = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (ValueError, UnicodeDecodeError, TypeError):
        _deny()
    if type(plan) is not dict or set(plan) != {"version", "tools"}:
        _deny()
    if type(plan["version"]) is not int or plan["version"] != 1:
        _deny()
    names = plan["tools"]
    if type(names) is not list or not 1 <= len(names) <= 64:
        _deny()
    if any(type(name) is not str or not _STATIC_ID.fullmatch(name) for name in names):
        _deny()
    if len(set(names)) != len(names):
        _deny()
    return tuple(names)


def _never_run(_context: RunContext, _args: dict) -> ToolOutput:
    raise AssertionError("offline CLI tool handler must never be executed")


def _preview(names: tuple[str, ...]) -> dict[str, int | bool | str]:
    # Only fixed, internally generated ANALYSIS metadata is registered.
    # No user-supplied capability, target, callback or handler is loaded.
    registry = ToolRegistry()
    for n in range(1, 65):
        tool_id = f"offline-check-{n:03d}"
        registry.register(
            ToolDefinition(
                tool_id, "network-services", InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY, "synthetic-only offline check",
            ),
            _never_run,
        )
    with tempfile.TemporaryDirectory(prefix="lightup-1307-plan-") as tmp:
        ledger = StateStore(Path(tmp) / "synthetic.sqlite")
        run_id = ledger.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        context = RunContext(
            run_id, "synthetic-client", "synthetic-engagement",
            AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
            None, False, datetime.now(timezone.utc),
        )
        executor = ToolExecutor(registry, ledger)
        inspector = OfflineExecutorBoundaryPreview.capture(executor)
        receipt = inspector.preview_batch(
            context,
            tuple(ToolCall(name, "synthetic.invalid") for name in names),
        )
        # Whitelist-only: never serialize user content or arbitrary instances.
        return {
            "status": "reviewed",
            "tools_reviewed": receipt.tools_reviewed,
            "permit_issued": False,
            "execution_enabled": False,
            "authorization_verified": False,
        }


def _compare(
    baseline: tuple[str, ...], proposed: tuple[str, ...]
) -> dict[str, int | bool | str]:
    """Read-only synthetic toolset delta; a green comparison grants nothing.

    Validate *both* plans by the same real offline preview before returning
    any summary, so even a late-invalid proposed plan has no partial receipt.
    This is not customer authorization or an active scope policy comparison.
    """
    _preview(baseline)
    _preview(proposed)
    old, new = set(baseline), set(proposed)
    return {
        "status": "reviewed",
        "added_tools": len(new - old),
        "removed_tools": len(old - new),
        "unchanged_tools": len(new & old),
        "expansion_detected": bool(new - old),
        "permit_issued": False,
        "execution_enabled": False,
        "authorization_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not (
        (len(args) == 2 and args[0] == "--input" and type(args[1]) is str)
        or (
            len(args) == 3
            and args[0] in ("--compare", "--require-no-expansion")
            and type(args[1]) is str
            and type(args[2]) is str
        )
    ):
        print(_GENERIC_ERROR, file=sys.stderr)
        return 2
    try:
        if args[0] == "--input":
            receipt = _preview(_load_plan(args[1]))
        else:
            baseline = _load_plan(args[1])
            proposed = _load_plan(args[2])
            receipt = _compare(baseline, proposed)
            # Optional strict CI-style signal. A widening synthetic plan
            # yields a constant denial with NO success receipt or plan data.
            # This does not issue/verify customer authorization.
            if args[0] == "--require-no-expansion" and receipt["expansion_detected"]:
                _deny()
    except Exception:
        # Opaque failure: no traceback, file path, plan data, host, or secret.
        print(_GENERIC_ERROR, file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
