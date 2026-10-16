"""Non-authorizing, standalone synthetic identity-shape review for LightUp #931.

NO LightUp imports, no network/targets, no customer data. This is NOT a
production identity/consent gate. A positive shape is always REVIEW_ONLY.
"""
from __future__ import annotations

import json
import os
import select
import stat
import sys
import time
import unicodedata

MAX_INPUT_BYTES = 4096
MAX_PROSPECT_LENGTH = 128
MAX_ORGANIZATION_LENGTH = 256
EXPECTED_KEYS = frozenset(("prospect_id", "organization_name"))
FALSE_FLAGS = ("authorization", "permit", "dispatch", "scan", "deploy", "release")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("nonfinite")


def _exact_nonblank(value: object, max_length: int) -> bool:
    if type(value) is not str or not value.strip():
        return False
    if len(value) > max_length:
        return False
    # Conservative offline screening: unusual controls/formats go to HOLD,
    # not normalization. Valid Unicode letters are not automatically denied.
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
           for char in value):
        return False
    return True


def review(raw: bytes) -> str:
    """Return only REVIEW_ONLY or HOLD; NEVER an authorization decision."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_INPUT_BYTES:
        return "HOLD"
    try:
        obj = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return "HOLD"
    if type(obj) is not dict or set(obj) != EXPECTED_KEYS:
        return "HOLD"
    if not _exact_nonblank(obj["prospect_id"], MAX_PROSPECT_LENGTH):
        return "HOLD"
    if not _exact_nonblank(obj["organization_name"], MAX_ORGANIZATION_LENGTH):
        return "HOLD"
    return "REVIEW_ONLY"


def receipt(status: str) -> str:
    # No caller-supplied values, identifiers, exception text or source paths.
    payload = {"status": status if status == "REVIEW_ONLY" else "HOLD"}
    payload.update({name: False for name in FALSE_FLAGS})
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _safe_streams() -> bool:
    """Use a distinct anonymous local pipe for input and a safe receipt sink."""
    try:
        input_fd, output_fd = sys.stdin.fileno(), sys.stdout.fileno()
        if (input_fd, output_fd) != (0, 1):
            return False
        source, destination = os.fstat(input_fd), os.fstat(output_fd)
        if not stat.S_ISFIFO(source.st_mode):
            return False  # Never implicitly read local files, devices or sockets.
        if not (
            stat.S_ISFIFO(destination.st_mode)
            or (stat.S_ISCHR(destination.st_mode) and os.isatty(output_fd))
        ):
            return False  # Never create a file or send a receipt to a socket.
        if (
            stat.S_ISFIFO(destination.st_mode)
            and (source.st_dev, source.st_ino)
            == (destination.st_dev, destination.st_ino)
        ):
            return False  # A receipt cannot become data on its own stdin pipe.
        return True
    except (OSError, ValueError, TypeError):
        return False


def _read_bounded_stdin() -> bytes | None:
    """Require EOF within two seconds; never trust a partial pipe as complete."""
    deadline = time.monotonic() + 2.0
    data = bytearray()
    try:
        fd = sys.stdin.fileno()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                return None
            chunk = os.read(fd, MAX_INPUT_BYTES + 1 - len(data))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > MAX_INPUT_BYTES:
                return None
    except (OSError, ValueError, TypeError):
        return None


def _write_receipt(status: str) -> bool:
    """Do not block forever or partially reveal a receipt into a full pipe."""
    try:
        fd = sys.stdout.fileno()
        message = (receipt(status) + "\n").encode("ascii")
        if stat.S_ISFIFO(os.fstat(fd).st_mode):
            _, writable, _ = select.select([], [fd], [], 0)
            if not writable:
                return False
        return os.write(fd, message) == len(message)
    except (OSError, ValueError, TypeError):
        return False


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Check endpoint type before touching potentially sensitive stdin.
    if not _safe_streams():
        return 2
    status = "HOLD"
    if argv == ["--offline-synthetic-only"]:
        raw = _read_bounded_stdin()
        if raw is not None:
            status = review(raw)
    if not _write_receipt(status):
        return 2
    return 3 if status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
