"""Fail-closed, read-only receipt for untrusted offline laboratory JSON.

The receipt is never a source or release validation. It only identifies bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat

MAX_BYTES = 262144
FALSE_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite JSON number")


def _read_private_regular(path):
    """Open the requested file itself without following its final symlink."""
    flags = os.O_RDONLY | os.O_NONBLOCK
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("no-follow unavailable")
    flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not a regular file")
        # A private handoff must not be readable by group/other or hard-linked.
        if before.st_mode & 0o077 or before.st_nlink != 1:
            raise ValueError("not private")
        if not 0 < before.st_size <= MAX_BYTES:
            raise ValueError("invalid size")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            data = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size,
                               st.st_mtime_ns, st.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError("source changed during read")
        return data
    finally:
        os.close(fd)


def inspect(path):
    """Return only an anonymous HOLD receipt, never validated source evidence."""
    receipt = {"status": "HOLD", "source_authenticated": False,
               "source_schema_verified": False,
               **{flag: False for flag in FALSE_FLAGS}}
    try:
        data = _read_private_regular(path)
        source = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_constant)
        if type(source) is not dict:
            return receipt
        if source.get("status") not in ("HOLD", "REVIEW_ONLY"):
            return receipt
        if any(source.get(flag) is not False for flag in FALSE_FLAGS):
            return receipt
        # No source value can promote the output to REVIEW_ONLY or authorize work.
        receipt.update(source_reported_status=source["status"],
                       source_sha256=hashlib.sha256(data).hexdigest(),
                       byte_count=len(data))
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        pass
    return receipt


if __name__ == "__main__":
    import sys
    print(json.dumps(inspect(sys.argv[1] if len(sys.argv) == 2 else ""), sort_keys=True))
    raise SystemExit(3)
