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


def _load_plan(path: str) -> tuple[str, ...]:
    # Opening a FIFO in blocking mode *before* checking fstat can hang this
    # CLI indefinitely. Nonblocking O_RDONLY ensures type validation runs
    # first. O_NOFOLLOW blocks symlink substitution of the final path.
    # These flags are required; no silent fallback to a weaker open.
    if not all(hasattr(os, flag) for flag in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC")):
        _deny()
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            _deny()
        # Explicit bounded kernel reads: no buffered prefetch, and a short
        # os.read() result cannot silently ignore trailing plan data.
        chunks: list[bytes] = []
        remaining = MAX_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size != before.st_size
        ):
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
            and args[0] == "--compare"
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
    except Exception:
        # Opaque failure: no traceback, file path, plan data, host, or secret.
        print(_GENERIC_ERROR, file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
