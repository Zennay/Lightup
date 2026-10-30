"""Open a previously verified source-free synthetic review as offline files.

Transport integrity is checked from a single immutable bounded ZIP snapshot
before any export is written; this never authenticates original source evidence
or grants any assessment authorization.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .lab_score_handoff_verify import _validated_portable_review
from .lab_score_inspect import _private_dir_fd
from .lab_score_suite import _private_output_directory


def unpack_portable_review(archive: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Publish the seven canonical, source-free members into a new 0700 dir.

    No generic ZIP extract APIs; filenames are from a fixed allowlist, not
    archive-provided paths. Each member is fsynced then linked without
    overwrite, and checked against the already-validated bytes. The
    destination stays owner-private. On error roll back only owned inodes.
    """
    result, files = _validated_portable_review(archive)
    source = Path(archive).expanduser().absolute()
    destination = Path(output_dir).expanduser().absolute()
    if (".." in Path(output_dir).parts or destination == source.parent
            or destination in source.parents or source in destination.parents):
        raise ValueError("review output overlaps original package")
    root = _private_output_directory(destination)
    fd = _private_dir_fd(root)
    published: list[tuple[str, tuple[int, int]]] = []
    try:
        try:
            for name in sorted(files):
                # Validated inventory consists of seven literal simple names.
                if name not in ("README.txt", "history.html", "index.html",
                                "manifest.json", "review.csv", "review.json", "review.md"):
                    raise ValueError("invalid portable review member")
                payload = files[name]
                temporary = "." + name + ".tmp"
                out = os.open(temporary, os.O_WRONLY | os.O_CREAT |
                              os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    with os.fdopen(out, "wb") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    meta = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                    identity = meta.st_dev, meta.st_ino
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd,
                            follow_symlinks=False)
                    published.append((name, identity))
                    os.unlink(temporary, dir_fd=fd)
                    reader = os.open(name, os.O_RDONLY | os.O_NOFOLLOW,
                                     dir_fd=fd)
                    try:
                        before = os.fstat(reader)
                        actual = os.pread(reader, len(payload) + 1, 0)
                        after = os.fstat(reader)
                        link = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (actual != payload or (before.st_dev, before.st_ino) != identity
                                or (link.st_dev, link.st_ino) != identity
                                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                            raise ValueError("portable file changed during publication")
                    finally:
                        os.close(reader)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
            if set(os.listdir(fd)) != set(files):
                raise ValueError("unexpected portable review files")
            os.fsync(fd)
        except Exception:
            for name, identity in reversed(published):
                try:
                    meta = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if (meta.st_dev, meta.st_ino) == identity:
                        os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    pass
            raise
    finally:
        os.close(fd)
    return result
