"""Fail-closed, read-only receipt for untrusted offline laboratory JSON.

The receipt is never a source or release validation. It only identifies bytes.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
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


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("out-of-range JSON decimal")
    return number


def _read_private_regular(path):
    """Pin every path component via dirfd; never follow any component symlink."""
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY")):
        raise ValueError("secure directory walk unsupported")
    path = os.fspath(path)
    if type(path) is not str or not path or "\\x00" in path:
        raise ValueError("invalid path")
    components = path.split("/")
    if os.path.isabs(path):
        components = components[1:]
        root = "/"
    else:
        root = "."
    # Reject traversal, alternate spellings and trailing slashes, not just symlinks.
    if not components or any(component in ("", ".", "..") for component in components):
        raise ValueError("noncanonical path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(root, directory_flags)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        fd = os.open(components[-1], flags, dir_fd=directory_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("not a regular file")
            if before.st_uid != os.geteuid():
                raise ValueError("file not owned by invoking account")
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
    finally:
        os.close(directory_fd)


def inspect(path, expected_sha256=None):
    """Return only an anonymous HOLD receipt, never validated source evidence."""
    receipt = {"status": "HOLD", "source_authenticated": False,
               "source_schema_verified": False,
               **{flag: False for flag in FALSE_FLAGS}}
    try:
        if expected_sha256 is not None and (
            type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_sha256)
        ):
            return receipt
        data = _read_private_regular(path)
        source = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_constant,
                            parse_float=_finite_float)
        if type(source) is not dict:
            return receipt
        if source.get("status") not in ("HOLD", "REVIEW_ONLY"):
            return receipt
        if any(source.get(flag) is not False for flag in FALSE_FLAGS):
            return receipt
        # Never disclose untrusted source metadata when byte custody mismatches.
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None:
            matches = secrets.compare_digest(digest, expected_sha256)
            if not matches:
                receipt["byte_identity_matches"] = False
                return receipt
            receipt["byte_identity_matches"] = True
        # No source value can promote the output to REVIEW_ONLY or authorize work.
        receipt.update(source_reported_status=source["status"],
                       source_sha256=digest,
                       byte_count=len(data))
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        pass
    return receipt


if __name__ == "__main__":
    import sys
    print(json.dumps(inspect(sys.argv[1] if len(sys.argv) in (2, 3) else "",
                             sys.argv[2] if len(sys.argv) == 3 else None),
                     sort_keys=True))
    raise SystemExit(3)
