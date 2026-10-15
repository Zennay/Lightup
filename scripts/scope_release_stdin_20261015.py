"""Bounded offline stdin for the two non-authorizing scope release reviewers.

No filesystem paths or networking are opened. Only explicitly connected
anonymous pipes or already-open regular-file stdin are read. Incomplete
streams have a single monotonic EOF deadline and fail closed.
"""
from __future__ import annotations

import os
import select
import stat
import time


class ReviewInputError(OSError):
    """A review input is not a complete, bounded local byte stream."""


def read_bounded_stdin(max_bytes: int, *, timeout_seconds: float = 2.0) -> bytes:
    if type(max_bytes) is not int or not 0 < max_bytes <= 65536:
        raise ReviewInputError("invalid byte budget")
    if type(timeout_seconds) is not float or not 0.0 < timeout_seconds <= 10.0:
        raise ReviewInputError("invalid read deadline")

    fd = 0
    info = os.fstat(fd)
    if not (stat.S_ISFIFO(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise ReviewInputError("stdin is not a local pipe or regular file")

    # Both tools operate only on a child process or an explicitly supplied
    # local file. Restore descriptor flags even when validation fails.
    old_blocking = os.get_blocking(fd)
    deadline = time.monotonic() + timeout_seconds
    data = bytearray()
    try:
        os.set_blocking(fd, False)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReviewInputError("stdin EOF deadline exceeded")
            try:
                ready, _, _ = select.select([fd], [], [], remaining)
            except InterruptedError:
                continue
            if not ready:
                raise ReviewInputError("stdin EOF deadline exceeded")
            try:
                block = os.read(fd, min(4096, max_bytes + 1 - len(data)))
            except BlockingIOError:
                continue
            if not block:
                return bytes(data)
            data.extend(block)
            if len(data) > max_bytes:
                raise ReviewInputError("stdin exceeds limit")
    finally:
        os.set_blocking(fd, old_blocking)
