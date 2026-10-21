"""Offline source-only PRIVATE installer; no extraction until canonical ZIP verified.

Install is not authority, provenance, consent, an assessment, or deployment.
No original lab source, customer materials, subprocesses or network are used.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import stat
import zipfile

import software_bundle as kit


def admitted_archive(path: str) -> bytes:
    """Re-admit the SAME bytes whose canonical manifest has been inspected.

    A source file can change between the independent manifest inspection
    and this read; digest equality binds the inspected and extracted bytes.
    """
    inspected = kit.inspect_unsigned_software(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
            raise ValueError("not a bounded regular source-only ZIP")
        with os.fdopen(fd, "rb", closefd=False) as source:
            content = source.read(1024 * 1024 + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or len(content) != before.st_size:
            raise ValueError("source ZIP changed during read")
        if hashlib.sha256(content).hexdigest() != inspected["sha256"]:
            raise ValueError("source ZIP differs from inspected unsigned package")
        return content
    finally:
        os.close(fd)


def install_private(archive: bytes, destination: str) -> int:
    """Publish software into a NEW 0700 directory under an EXISTING private parent.

    All child files are 0600 and opened relative to pinned directory FDs.
    A failure normally cleans only names created by this invocation.
    """
    target = Path(destination)
    if target.name in ("", ".", ".."):
        raise ValueError("destination must be a new child directory name")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(target.parent, flags)
    outer_fd = None
    inner_fd = None
    outer_created = False
    inner_created = False
    written = []
    success = False
    try:
        parent_info = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent_info.st_mode) or
            parent_info.st_uid != os.geteuid() or
            (stat.S_IMODE(parent_info.st_mode) & 0o077)):
            raise ValueError("private parent must be user-owned and inaccessible to group/others")
        with zipfile.ZipFile(io.BytesIO(archive), "r") as source:
            expected = [kit.PREFIX + item for item in kit.SOFTWARE_FILES]
            expected += [kit.PREFIX + "MANIFEST.json"]
            if sorted(source.namelist()) != sorted(expected):
                raise ValueError("unexpected source-only software member")
            # Only after all source bytes have passed admission create the destination.
            os.mkdir(target.name, 0o700, dir_fd=parent_fd)
            outer_created = True
            outer_fd = os.open(target.name, flags, dir_fd=parent_fd)
            os.mkdir(kit.PREFIX.rstrip("/"), 0o700, dir_fd=outer_fd)
            inner_created = True
            inner_fd = os.open(kit.PREFIX.rstrip("/"), flags, dir_fd=outer_fd)
            for member in sorted(expected):
                basename = member[len(kit.PREFIX):]
                if not basename or "/" in basename or basename in (".", ".."):
                    raise ValueError("unsafe member path")
                bytes_data = source.read(member)
                outfd = os.open(basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=inner_fd)
                written.append(basename)
                try:
                    with os.fdopen(outfd, "wb", closefd=False) as out:
                        out.write(bytes_data)
                        out.flush()
                    os.fchmod(outfd, 0o600)
                    os.fsync(outfd)
                finally:
                    os.close(outfd)
            os.fsync(inner_fd)
            os.fsync(outer_fd)
            os.fsync(parent_fd)
            success = True
            return len(written)
    finally:
        if not success:
            if inner_fd is not None:
                for name in reversed(written):
                    try:
                        os.unlink(name, dir_fd=inner_fd)
                    except FileNotFoundError:
                        pass
        if inner_fd is not None:
            os.close(inner_fd)
        if not success and inner_created and outer_fd is not None:
            try:
                os.rmdir(kit.PREFIX.rstrip("/"), dir_fd=outer_fd)
            except OSError:
                pass
        if outer_fd is not None:
            os.close(outer_fd)
        if not success and outer_created:
            try:
                os.rmdir(target.name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Install unsigned source-only LightUp kit into a NEW PRIVATE 0700 directory")
    parser.add_argument("--zip", required=True, dest="archive", help="existing original software ZIP")
    parser.add_argument("--private-dir", required=True, help="new child under existing owner-only 0700 parent")
    args = parser.parse_args()
    try:
        raw = admitted_archive(args.archive)
        installed = install_private(raw, args.private_dir)
    except (OSError, ValueError, UnicodeError, MemoryError, zipfile.BadZipFile, RuntimeError):
        print("HOLD: refused unsigned kit or private destination; no authorization")
        return 3
    print("REVIEW_ONLY: installed", installed, "unsigned software-only files in new owner-only directory")
    print("Open assessment-disclosure-preflight/kit-home.html locally; no scanning, consent or release")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
