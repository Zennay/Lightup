#!/usr/bin/env python3
"""Offline read-only comparison, never an authorization or merge gate."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

# Allow direct repository-root script execution without packaging.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.capability_registry_drift_review import review_capability_registry_drift

_MAX = 32768


def read_local_regular_file(path: str) -> tuple[bytes, tuple[int, int]]:
    flags = os.O_RDONLY
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("safe file open not supported")
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= _MAX:
            raise ValueError("file must be a bounded regular file")
        data = os.read(fd, _MAX + 1)
        last = os.fstat(fd)
        if len(data) != st.st_size or (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (
            last.st_ino, last.st_dev, last.st_size, last.st_mtime_ns, last.st_ctime_ns
        ):
            raise ValueError("file modified during read")
        return data, (st.st_dev, st.st_ino)
    finally:
        os.close(fd)


def main(args: list[str]) -> int:
    if len(args) != 2:
        receipt = {"status": "HOLD", "reason": "expected_two_local_manifest_paths"}
    else:
        try:
            baseline, original_identity = read_local_regular_file(args[0])
            candidate, candidate_identity = read_local_regular_file(args[1])
            if original_identity == candidate_identity:
                receipt = {"status": "HOLD", "reason": "same_file_is_not_two_snapshots"}
            else:
                receipt = review_capability_registry_drift(baseline, candidate).as_dict()
        except (OSError, ValueError, TypeError):
            receipt = {"status": "HOLD", "reason": "unreadable_local_manifest"}
    for key in ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved"):
        receipt[key] = False
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
