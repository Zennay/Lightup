#!/usr/bin/env python3
"""Build and inspect a source-only PRIVATE offline LightUp remediation suite.

No user input, tenant files, live endpoints, consent, grants, or scanning.
A source lock and unkeyed hashes are local consistency only, NEVER provenance.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib

# inspect-archive promises no filesystem output. Python otherwise creates
# __pycache__ for imported local renderer, desk and recipient modules.
# Prevent cache writes when launched as the native CLI, BEFORE local imports.
# Other callers importing this library retain their own Python cache policy.
if __name__ == "__main__":
    sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "remediation-integrated-workspace" / "source-lock.json"
KIND = "lightup.private_offline_remediation_suite"
ROOTS = frozenset((
    "casework", "remediation-artifact-ledger", "remediation-evidence-reuse",
    "remediation-evidence-bundle-integrity", "remediation-recipient-trend",
    "remediation-portfolio", "remediation-human-handoff",
))
WARNING = ("PRIVATE HUMAN-only offline software. No original producer authentication, "
           "consent, grant, security finding, remediation, verified retest or HUMAN GO. "
           "INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD.")
MAX_SOURCE = 4_000_000
MAX_TOTAL = 15_000_000

INTEGRATED_TOOLS = (
    "remediation-integrated-workspace/install.py",
    "remediation-integrated-workspace/private_desk.py",
    "remediation-integrated-workspace/operator_console.py",
    "remediation-integrated-workspace/landing.py",
    "remediation-integrated-workspace/operator_ui.js",
    "remediation-integrated-workspace/fingerprint_ui.js",
    "remediation-integrated-workspace/packet_fingerprint.py",
    "remediation-integrated-workspace/packet_brief.py",
    "remediation-integrated-workspace/operator_ui.css",
    "remediation-integrated-workspace/receiver.py",
    "remediation-integrated-workspace/workflow.py",
    "remediation-integrated-workspace/portable_cockpit.py",
    "remediation-integrated-workspace/single_review.py",
    "remediation-integrated-workspace/single_review.js",
    "remediation-integrated-workspace/single_brief.py",
    "remediation-integrated-workspace/SINGLE_REVIEW.md",
    "remediation-integrated-workspace/archive_workflow.py",
    "remediation-integrated-workspace/encrypted_cockpit.py",
    "remediation-integrated-workspace/journal_vault.py",
    "remediation-integrated-workspace/journal_encrypt.js",
    "remediation-integrated-workspace/journal_open.js",
    "remediation-integrated-workspace/review_package.py",
    "remediation-integrated-workspace/REVIEW_PACKAGE.md",
    "remediation-integrated-workspace/JOURNAL_VAULT.md",
    "remediation-integrated-workspace/README.md",
)

class Hold(ValueError):
    pass

def require(ok: bool, message: str) -> None:
    if not ok:
        raise Hold(message)

def require_operator_path(path: Path) -> None:
    """Reject terminal-control/bidi spoofing in native HUMAN CLI paths.

    The browser composer already rejects ASCII control characters, but
    operators may run the native CLI without its browser preview. Original
    path strings are echoed in HUMAN review instructions and must not
    contain terminal escape controls or direction-changing Unicode marks.
    This does not authenticate the path or its owner: nofollow/private
    descriptor admission remains the actual filesystem gate.
    """
    require(isinstance(path, Path) and path.is_absolute(),
            "HOLD: expected a literal absolute HUMAN operator path")
    name = os.fspath(path)
    # POSIX reserves two leading slashes for implementation-defined path
    # semantics. The offline browser already rejects this ambiguous form;
    # native entrypoints must not reinterpret it as an ordinary root path.
    require(name.startswith("/") and not name.startswith("//"),
            "HOLD: use one literal leading slash for a private Linux path")
    # Unicode general categories catch invisible marks overlooked by a
    # blacklist: Cf (ZWSP, soft hyphen, word joiner, bidi controls),
    # Cc (including C1 terminal controls), Cs (surrogates), and actual
    # line/paragraph separators. Printable Unicode names remain allowed.
    disallowed = {"Cc", "Cf", "Cs", "Zl", "Zp"}
    require(0 < len(name) <= 1024 and
            all(unicodedata.category(ch) not in disallowed for ch in name) and
            all(part not in (".", "..") for part in path.parts[1:]),
            "Operator path contains invisible format/control marks or unsafe segments")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")

def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "Duplicate JSON member")
        result[key] = value
    return result

def parse(raw: bytes) -> dict:
    require(len(raw) <= 350_000, "JSON descriptor too large")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold("Nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Hold("Invalid JSON descriptor") from exc
    require(type(obj) is dict and canonical(obj) == raw, "Noncanonical descriptor")
    return obj

def open_literal_read_fd(path: Path, *, private_parent: bool = False) -> int:
    """Pin every directory component before opening the final file.

    O_NOFOLLOW on the final pathname alone still follows swapped parent
    directory symlinks. Traverse each directory via dir_fd/O_DIRECTORY and
    O_NOFOLLOW, keeping the selected chain descriptor-bound. O_NONBLOCK on the
    last file also prevents a race-replaced FIFO from blocking before fstat.
    Linux-only, matching this suite's exclusive Linux publisher.
    """
    require(path.is_absolute() and len(path.parts) >= 2
            and all(part not in (".", "..") for part in path.parts[1:]),
            "A literal absolute file path is required")
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY |
             getattr(os, "O_CLOEXEC", 0))
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if private_parent:
            parent = os.fstat(fd)
            require(stat.S_ISDIR(parent.st_mode) and
                    parent.st_uid == os.getuid() and
                    parent.st_mode & 0o077 == 0,
                    "Private source parent must be owner-only")
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                       getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
                       dir_fd=fd)
    finally:
        os.close(fd)


def read_checkout_source(path: Path, ceiling: int = MAX_SOURCE) -> bytes:
    """Admit a fixed local software file via one no-follow descriptor.

    Reject linked components, partial/changed reads and mutable file identity.
    This checks local bytes, not ownership of the upstream producer.
    """
    require(path.is_absolute() and ROOT in path.parents and
            path != ROOT and 0 < ceiling <= MAX_TOTAL,
            "Source must be an exact file beneath the current checkout")
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode), "Linked checkout path refused")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 <= before.st_size <= ceiling, "Unsafe or oversized checkout source")
    fd = open_literal_read_fd(path)
    try:
        current = os.fstat(fd)
        identity = (current.st_dev, current.st_ino, current.st_size,
                    current.st_mtime_ns, current.st_ctime_ns)
        require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                and identity == (before.st_dev, before.st_ino, before.st_size,
                                 before.st_mtime_ns, before.st_ctime_ns),
                "Checkout source changed during admission")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(ceiling + 1)
        after = os.fstat(fd)
        post = path.lstat()
        require((after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) == identity
                and (post.st_dev, post.st_ino, post.st_size,
                     post.st_mtime_ns, post.st_ctime_ns) == identity
                and stat.S_ISREG(post.st_mode) and post.st_nlink == 1
                and len(raw) == current.st_size and len(raw) <= ceiling,
                "Checkout source changed while reading")
        return raw
    finally:
        os.close(fd)


def safe_name(name: str) -> bool:
    if type(name) is not str or not 1 <= len(name) <= 190:
        return False
    p = PurePosixPath(name)
    return (not p.is_absolute() and len(p.parts) >= 2
            and p.parts[0] in ROOTS
            and all(part not in (".", "..") and not part.startswith(".") for part in p.parts)
            and p.suffix in (".py", ".md", ".html", ".js", ".css")
            and all(ord(c) < 128 and (c.isalnum() or c in "/_.-") for c in name))

def require_native_archive(archive: zipfile.ZipFile, expected_names: set[str]) -> None:
    """Admit only our fixed portable software-only ZIP layout.

    File checksums alone cannot detect changed ZIP metadata, unexpected
    comments, encryption flags or non-original path formats. This does not
    assert ZIP producer identity or trust the bytes beyond local consistency.
    """
    members = archive.infolist()
    require(archive.comment == b"" and
            [entry.filename for entry in members] == sorted(expected_names),
            "Noncanonical software ZIP inventory or archive comment")
    require(all(entry.date_time == (2020, 1, 1, 0, 0, 0)
                and entry.create_system == 3
                and (entry.external_attr >> 16) == 0o100600
                and entry.compress_type == zipfile.ZIP_DEFLATED
                and entry.flag_bits == 0
                and entry.extra == b"" and entry.comment == b""
                and entry.internal_attr == 0
                and not entry.is_dir()
                and 0 <= entry.file_size <= MAX_SOURCE
                and 0 <= entry.compress_size <= MAX_SOURCE
                for entry in members)
            and sum(entry.file_size for entry in members) <= MAX_TOTAL,
            "Unsafe or noncanonical software ZIP member metadata")



def unpack_native_archive(raw: bytes, expected_names: set[str]) -> dict[str, bytes]:
    """Admit complete canonical ZIP headers, directory and contents offline.

    zipfile alone accepts harmless-looking prepended/trailing data and some
    alternate local/central header layouts. No re-compression is required:
    different native zlib builds can encode the same verified source bytes.
    This proves local structural consistency, NEVER author identity.
    """
    import io
    require(0 < len(raw) <= MAX_TOTAL, "Software ZIP exceeds bound")
    # Malformed incoming DEFLATE streams must produce the same native HOLD
    # contract as damaged ZIP headers or incorrect source digests, never an
    # uncaught lower-level stacktrace on an authorized operator terminal.
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            require_native_archive(archive, expected_names)
            members = archive.infolist()
            require(len(raw) >= 22 and len(members) < 0xffff,
                    "Noncanonical ZIP directory size")
            local_pos = 0
            for member in members:
                name = member.filename.encode("ascii")
                require(member.header_offset == local_pos and
                        len(raw) - local_pos >= 30, "Unexpected ZIP local header offset")
                local = struct.unpack_from("<I5H3I2H", raw, local_pos)
                # signature, reader version, flags, method, DOS time/date,
                # CRC, deflated/raw sizes, raw filename length and extra length
                require(local == (0x04034b50, 20, 0, 8, 0, 20513,
                                  member.CRC, member.compress_size,
                                  member.file_size, len(name), 0),
                        "Noncanonical ZIP local header")
                require(raw[local_pos + 30:local_pos + 30 + len(name)] == name,
                        "Changed local ZIP filename")
                local_pos += 30 + len(name) + member.compress_size
                require(local_pos <= len(raw), "Truncated ZIP member data")
            require(local_pos == archive.start_dir,
                    "Unexpected ZIP prefix, local records or padding")
            central_pos = local_pos
            for member in members:
                name = member.filename.encode("ascii")
                require(len(raw) - central_pos >= 46, "Truncated ZIP central header")
                central = struct.unpack_from("<I6H3I5H2I", raw, central_pos)
                require(central == (0x02014b50, 0x0314, 20, 0, 8, 0, 20513,
                                    member.CRC, member.compress_size,
                                    member.file_size, len(name), 0, 0, 0, 0,
                                    0o100600 << 16, member.header_offset),
                        "Noncanonical ZIP central header")
                require(raw[central_pos + 46:central_pos + 46 + len(name)] == name,
                        "Changed central ZIP filename")
                central_pos += 46 + len(name)
            require(len(raw) - central_pos == 22 and
                    struct.unpack_from("<I4H2IH", raw, central_pos) ==
                    (0x06054b50, 0, 0, len(members), len(members),
                     central_pos - archive.start_dir, archive.start_dir, 0),
                    "ZIP end record, trailing bytes, or directory boundary changed")
            return {member.filename: archive.read(member) for member in members}
    except (zipfile.BadZipFile, zlib.error, struct.error, EOFError) as exc:
        raise Hold("Corrupt or incomplete native software ZIP") from exc


def catalog() -> tuple[bytes, dict]:
    raw = read_checkout_source(LOCK, 350_000)
    obj = parse(raw)
    require(obj is not None and set(obj) == {"kind", "version", "source_heads", "files"}
            and obj["kind"] == "lightup.integrated_offline_source_lock"
            and type(obj["version"]) is int and obj["version"] == 1, "Invalid source inventory")
    entries = obj["files"]
    require(type(entries) is dict and 50 <= len(entries) <= 160, "Incomplete source inventory")
    require(sum(v.get("bytes", MAX_TOTAL) for v in entries.values() if type(v) is dict) <= MAX_TOTAL,
            "Oversized source inventory")
    for name, descriptor in entries.items():
        require(safe_name(name), "Unsafe source name")
        require(type(descriptor) is dict and set(descriptor) == {"sha256", "bytes"}
                and type(descriptor["bytes"]) is int
                and 0 <= descriptor["bytes"] <= MAX_SOURCE
                and type(descriptor["sha256"]) is str
                and len(descriptor["sha256"]) == 64
                and all(ch in "0123456789abcdef" for ch in descriptor["sha256"]),
                "Invalid source descriptor")
    return raw, obj

def owner_dir(folder: Path) -> None:
    require(folder.is_absolute() and not folder.is_symlink()
            and folder.parent == folder.parent.resolve(strict=True),
            "Directory must be absolute, literal, non-symlink path")
    s = folder.stat(follow_symlinks=False)
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
            and s.st_mode & 0o077 == 0, "Directory must be owner-only 0700")

def read_owner_file(path: Path, ceiling: int = MAX_SOURCE) -> bytes:
    """Admit an exact owner-private file with its explicitly declared size cap.

    Source files retain the per-file source bound. Only the known portable
    ZIP call sites request the larger 15 MB total archive bound.
    """
    require(type(ceiling) is int and 0 < ceiling <= MAX_TOTAL,
            "Invalid private input size limit")
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
            and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600,
            "Private original file must have exact 0600 mode and one link")
    fd = open_literal_read_fd(path, private_parent=True)
    try:
        fs = os.fstat(fd)
        identity = (fs.st_dev, fs.st_ino, fs.st_size, fs.st_mtime_ns, fs.st_ctime_ns)
        require(stat.S_ISREG(fs.st_mode) and fs.st_uid == os.getuid()
                and fs.st_nlink == 1 and stat.S_IMODE(fs.st_mode) == 0o600
                and identity == (s.st_dev, s.st_ino, s.st_size,
                                 s.st_mtime_ns, s.st_ctime_ns)
                and 0 <= fs.st_size <= ceiling,
                "File changed or unsafe during private admission")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(fs.st_size + 1)
        after = os.fstat(fd)
        updated = path.lstat()
        require((after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) == identity
                and (updated.st_dev, updated.st_ino, updated.st_size,
                     updated.st_mtime_ns, updated.st_ctime_ns) == identity
                and stat.S_ISREG(updated.st_mode)
                and updated.st_uid == os.getuid() and updated.st_nlink == 1
                and stat.S_IMODE(updated.st_mode) == 0o600
                and len(raw) == fs.st_size,
                "Private input replaced, changed mode, or modified during read")
        return raw
    finally:
        os.close(fd)

def open_private_dir_fd(path: Path) -> int:
    """Keep an exact original 0700 directory open, never following any link."""
    require(path.is_absolute() and
            all(part not in (".", "..") for part in path.parts[1:]),
            "A literal absolute owner-only directory is required")
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY |
             getattr(os, "O_CLOEXEC", 0))
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        desc = os.fstat(fd)
        require(stat.S_ISDIR(desc.st_mode) and
                desc.st_uid == os.getuid() and desc.st_mode & 0o077 == 0,
                "Private directory must be current-user 0700")
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)



def create_private_stage(parent: Path, prefix: str) -> tuple[Path, tuple[int, int]]:
    """Create a fresh 0700 stage and keep its original device/inode identity.

    The pathname is only reused by existing nofollow file admission after
    creation. This does not grant authority or defeat same-user modification
    of an otherwise writable checkout.
    """
    require(prefix in (".lightup-suite-", ".lightup-integrity-", ".lightup-receiver-"),
            "Unknown private staging namespace")
    stage = parent / (prefix + secrets.token_hex(12))
    parent_fd = open_private_dir_fd(parent)
    created = False
    try:
        os.mkdir(stage.name, mode=0o700, dir_fd=parent_fd)
        created = True
        child_fd = os.open(stage.name,
                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                           getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            state = os.fstat(child_fd)
            require(stat.S_ISDIR(state.st_mode) and state.st_uid == os.getuid()
                    and stat.S_IMODE(state.st_mode) == 0o700,
                    "Fresh stage must be a single owner-private directory")
        finally:
            os.close(child_fd)
        os.fsync(parent_fd)
        # Name and 0700 mode alone cannot identify the directory later.
        return stage, (state.st_dev, state.st_ino)
    except BaseException:
        # A caller's finally only starts after this factory returns. If
        # fstat/open/fsync fails after mkdir, remove ONLY the fresh, EMPTY
        # original stage using the still-pinned private parent descriptor.
        # Do not recursively delete another actor's substituted contents.
        if created:
            try:
                os.rmdir(stage.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass  # Preserve the first HOLD/error; never delete unknown data.
        raise
    finally:
        os.close(parent_fd)



def ensure_private_subdirs(root: Path, member: str) -> None:
    """Make a member's private parent directories by anchored Linux dirfds.

    pathlib.mkdir(parents=True) uses absolute paths, and could follow a
    replaced intermediate directory symlink. Every existing or newly made
    component here is opened with O_DIRECTORY|O_NOFOLLOW and must be the
    current user's exact 0700 directory; no arbitrary files are admitted.
    The last member component is written separately with exclusive nofollow.
    """
    require(type(member) is str and len(member) > 0
            and not member.startswith("/")
            and all(part not in ("", ".", "..") for part in member.split("/")),
            "Unsafe installed member directory path")
    flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
             getattr(os, "O_CLOEXEC", 0))
    fd = open_private_dir_fd(root)
    try:
        for part in PurePosixPath(member).parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, flags, dir_fd=fd)
            try:
                state = os.fstat(next_fd)
                require(stat.S_ISDIR(state.st_mode)
                        and state.st_uid == os.getuid()
                        and stat.S_IMODE(state.st_mode) == 0o700,
                        "Installed member parent must be exact owner-only 0700")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
    finally:
        os.close(fd)


def cleanup_private_stage(stage: Path, identity: tuple[int, int]) -> None:
    """Clean only the original stage inode, never a same-owner replacement.

    A second private 0700 directory under the valid random staging name is
    NOT our original directory. Anchored rmtree never follows symlinks.
    A malicious process controlling the same Unix user remains out of scope.
    """
    prefixes = (".lightup-suite-", ".lightup-integrity-", ".lightup-receiver-")
    require(stage.is_absolute() and
            any(stage.name.startswith(prefix) and
                len(stage.name) == len(prefix) + 24 and
                all(ch in "0123456789abcdef" for ch in stage.name[len(prefix):])
                for prefix in prefixes),
            "Refusing to clean an unknown private staging path")
    require(type(identity) is tuple and len(identity) == 2
            and all(type(value) is int and value >= 0 for value in identity),
            "Original private stage identity required for cleanup")
    parent_fd = open_private_dir_fd(stage.parent)
    try:
        try:
            original = os.stat(stage.name, dir_fd=parent_fd,
                               follow_symlinks=False)
        except FileNotFoundError:
            return  # Already published with exclusive no-replace rename.
        require(stat.S_ISDIR(original.st_mode) and
                original.st_uid == os.getuid() and
                stat.S_IMODE(original.st_mode) == 0o700 and
                (original.st_dev, original.st_ino) == identity,
                "Refusing to clean a replaced or unsafe private stage")
        # shutil.rmtree uses fd-relative nofollow traversal on this Linux
        # host; no mutable absolute parent is used during removal.
        shutil.rmtree(stage.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def cleanup_private_file_stage(stage: Path, identity: tuple[int, int]) -> None:
    """Discard only the exact original temporary checksum inode.

    Never follow a substituted path. Even same-owner, same-mode replacement
    is NOT the file this worker created, and must never be unlinked by us.
    """
    require(stage.is_absolute() and
            stage.name.startswith(".lightup-software-hash-") and
            len(stage.name) == len(".lightup-software-hash-") + 24 and
            all(c in "0123456789abcdef"
                for c in stage.name[len(".lightup-software-hash-"):]),
            "Unknown private checksum staging entry")
    require(type(identity) is tuple and len(identity) == 2
            and all(type(v) is int and v >= 0 for v in identity),
            "Original checksum inode identity required")
    parent_fd = open_private_dir_fd(stage.parent)
    try:
        try:
            original = os.stat(stage.name, dir_fd=parent_fd,
                               follow_symlinks=False)
        except FileNotFoundError:
            return  # renameat2(NO_REPLACE) published the original entry.
        require(stat.S_ISREG(original.st_mode) and
                original.st_uid == os.getuid() and
                stat.S_IMODE(original.st_mode) == 0o600 and
                original.st_nlink == 1 and
                (original.st_dev, original.st_ino) == identity,
                "Private checksum stage was replaced or became unsafe")
        os.unlink(stage.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def write_file(path: Path, payload: bytes) -> tuple[int, int]:
    """Publish a new 0600 file and return the exact descriptor-backed inode.

    Other callers may discard the identity. The checksum writer uses it to
    prevent deleting a replaced stage during cleanup.
    """
    require(path.is_absolute() and path.name not in (".", ".."),
            "A literal absolute output file path is required")
    parent_fd = open_private_dir_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=parent_fd)
        try:
            # Remember the exact newly created inode *before* any byte write
            # or fsync can fail. A checksum caller otherwise receives no
            # identity and cannot safely clean its incomplete 0600 stage.
            original = os.fstat(fd)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=False) as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
                # Persist both contents and the private directory entry.
                # Keep the original nofollow parent fd pinned throughout.
                os.fsync(parent_fd)
                state = os.fstat(fd)
                return state.st_dev, state.st_ino
            except BaseException:
                # Roll back only our original private single-link inode when
                # writing or syncing fails. Never unlink a symlink, another
                # file's inode or a substituted directory entry.
                try:
                    current = os.stat(path.name, dir_fd=parent_fd,
                                      follow_symlinks=False)
                    if (stat.S_ISREG(current.st_mode) and
                            current.st_uid == os.getuid() and
                            current.st_nlink == 1 and
                            (current.st_dev, current.st_ino) ==
                            (original.st_dev, original.st_ino)):
                        os.unlink(path.name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                except OSError:
                    pass  # Preserve the original write failure.
                raise
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)

def home() -> bytes:
    # Single source-of-truth for the complete PRIVATE scriptless entry page.
    import landing
    return landing.render()

def exclusive_publish(stage: Path, destination: Path,
                      *, expected_identity: tuple[int, int] | None = None) -> None:
    """Publish only the original staged inode with Linux NO_REPLACE.

    Current native callers supply the device/inode obtained at original
    private creation; older independently owned workflows can still use
    the existing no-replace API until their original owners integrate it.
    This catches accidental or substituted staged entries at publication,
    not malicious same-user changes between filesystem operations.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, "renameat2", None)
    require(operation is not None, "Exclusive Linux recipient publication unavailable")
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    require(stage.is_absolute() and destination.is_absolute()
            and stage.parent == destination.parent
            and stage.name not in (".", "..")
            and destination.name not in (".", ".."),
            "Exclusive publication needs one literal private parent")
    # Both names remain relative to one pinned 0700 directory descriptor.
    # This avoids following a replaced parent symlink during the final rename.
    fd = open_private_dir_fd(destination.parent)
    try:
        if expected_identity is not None:
            require(type(expected_identity) is tuple and
                    len(expected_identity) == 2 and
                    all(type(v) is int and v >= 0 for v in expected_identity),
                    "Original staging inode identity must be exact")
            original = os.stat(stage.name, dir_fd=fd, follow_symlinks=False)
            private_mode = (stat.S_ISDIR(original.st_mode)
                            and stat.S_IMODE(original.st_mode) == 0o700)
            private_file = (stat.S_ISREG(original.st_mode)
                            and stat.S_IMODE(original.st_mode) == 0o600
                            and original.st_nlink == 1)
            require((original.st_dev, original.st_ino) == expected_identity
                    and original.st_uid == os.getuid()
                    and (private_mode or private_file),
                    "Original private publishing stage was replaced or became unsafe")
        rc = operation(fd, os.fsencode(stage.name), fd,
                       os.fsencode(destination.name), 1)
        if rc:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number), str(destination))
        os.fsync(fd)
    finally:
        os.close(fd)

def build(dest: Path) -> None:
    lock_raw, lock = catalog()
    require(dest.is_absolute() and not dest.exists() and not dest.is_symlink()
            and dest.parent == dest.parent.resolve(strict=True), "Choose a new literal absolute destination")
    owner_dir(dest.parent)
    require(dest != ROOT and ROOT not in dest.parents and dest not in ROOT.parents,
            "Output must be separate from the original source checkout")
    stage, stage_identity = create_private_stage(dest.parent, ".lightup-suite-")
    try:
        written = {}
        entries = {}
        for name, descriptor in sorted(lock["files"].items()):
            original = ROOT / name
            raw = read_checkout_source(original)
            require(len(raw) == descriptor["bytes"] and
                    digest(raw) == descriptor["sha256"],
                    "Original source bytes differ from the pinned source inventory")
            target = stage / name
            ensure_private_subdirs(stage, name)
            write_file(target, raw)
            written[name] = raw
            entries[name] = descriptor
        # Make the archive independently inspectable on a second offline
        # authorized device: carry this CLI and its operator guide too.
        for name in INTEGRATED_TOOLS:
            data = read_checkout_source(ROOT / name)
            dest_file = stage / name
            ensure_private_subdirs(stage, name)
            write_file(dest_file, data)
            written[name] = data
            entries[name] = {"sha256": digest(data), "bytes": len(data)}
        import operator_console
        operator_page = operator_console.render()
        landing = home()
        written["operator.html"] = operator_page
        written["index.html"] = landing
        written["source-lock.json"] = lock_raw
        for name in ("index.html", "operator.html", "source-lock.json"):
            write_file(stage / name, written[name])
            entries[name] = {"sha256": digest(written[name]), "bytes": len(written[name])}
        archive = stage / "software-only.zip"
        # The ZIP must be owner-private at creation, not chmod'ed only after
        # ZipFile(path, "w") has opened it with the process default umask.
        # O_EXCL + O_NOFOLLOW protect the original staged ZIP name, and
        # dir_fd anchors it to this exact fresh owner-only suite directory.
        directory_fd = open_private_dir_fd(stage)
        try:
            archive_fd = os.open(archive.name, os.O_RDWR | os.O_CREAT |
                                 os.O_EXCL | os.O_NOFOLLOW |
                                 getattr(os, "O_CLOEXEC", 0),
                                 0o600, dir_fd=directory_fd)
            with os.fdopen(archive_fd, "w+b") as archive_stream:
                os.fchmod(archive_stream.fileno(), 0o600)
                with zipfile.ZipFile(archive_stream, "w",
                                     compression=zipfile.ZIP_DEFLATED,
                                     compresslevel=8) as z:
                    for name, data in sorted(written.items()):
                        info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = 0o100600 << 16
                        info.create_system = 3
                        z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=8)
                archive_stream.flush()
                os.fsync(archive_stream.fileno())
            # Persist the new ZIP directory entry as well as its contents,
            # using the SAME pinned private parent fd held since O_EXCL.
            # Without fsync(dir), a crash can lose the name after fsync(file).
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        archive_raw = read_owner_file(archive, ceiling=MAX_TOTAL)
        entries["software-only.zip"] = {"sha256": digest(archive_raw),
                                         "bytes": len(archive_raw)}
        receipt = {"kind": KIND, "version": 1, "disposition": "HUMAN_ONLY_DRAFT_HOLD",
                   "authority_granted": False, "scan_authorized": False,
                   "verified_remediation": False, "client_consent": False,
                   "source_heads": lock["source_heads"], "files": entries,
                   "warning": WARNING}
        write_file(stage / "manifest.json", canonical(receipt))
        # Re-admit the immutable pinned sources and the assembled software tools
        # immediately before publication; never publish a source-mixed workspace.
        require(read_checkout_source(LOCK, 350_000) == lock_raw,
                "Source lock changed during build")
        for name, descriptor in lock["files"].items():
            fresh = read_checkout_source(ROOT / name)
            require(len(fresh) == descriptor["bytes"] and
                    digest(fresh) == descriptor["sha256"],
                    "Pinned source changed during build")
        for name in written:
            if name.startswith("remediation-integrated-workspace/"):
                require(read_checkout_source(ROOT / name) == written[name],
                        "Installer software changed during build")
        # Check the actual complete staged software and archive before
        # exclusive publication; any HOLD removes this unpublished stage.
        verify(stage, compare_checkout=True)
        require(not dest.exists(), "Destination appeared during build")
        exclusive_publish(stage, dest, expected_identity=stage_identity)
        print("PRIVATE offline integrated workspace:", dest)
        print("Open locally:", dest / "index.html")
        print("Software-only archive:", dest / "software-only.zip")
        print("REVIEW_ONLY / NO AUTHORITY; original release gates remain held.")
    finally:
        cleanup_private_stage(stage, stage_identity)

def passport_material(receipt: dict, verified: dict[str, bytes],
                      checkout_compared: bool) -> tuple[bytes, bytes]:
    """Rebuild the exact original offline review-only passport, without IO."""
    # Also enforce the release-evidence invariant at the material factory.
    # Never produce or re-admit a "reproducibility" report from a merely
    # self-consistent unsigned package, even through a direct Python caller.
    require(checkout_compared is True,
            "A reproducibility passport requires explicit checkout parity")
    manifest = canonical(receipt)
    report = {
        "kind": "lightup.offline_software_reproducibility_passport",
        "version": 1,
        "disposition": "HUMAN_ONLY_DRAFT_HOLD",
        "source_heads": receipt["source_heads"],
        "installed_software_file_count": len(verified) - 1,
        "pinned_original_file_count": len(catalog()[1]["files"]),
        "manifest_sha256_unsigned": digest(manifest),
        "software_archive_sha256_unsigned": digest(verified["software-only.zip"]),
        "compared_to_explicit_checkout": checkout_compared,
        "checkout_verified_file_count": len(verified) - 4,
        "authority_granted": False,
        "client_consent": False,
        "scan_authorized": False,
        "verified_evidence": False,
        "verified_remediation": False,
        "release_approved": False,
        "warning": WARNING,
    }
    import html

    def field(label: str, value: object, *, code: bool = False) -> str:
        safe_label = html.escape(label)
        safe_value = html.escape(str(value), quote=True)
        if code:
            safe_value = "<code>" + safe_value + "</code>"
        return "<div class=\"field\"><dt>" + safe_label + "</dt><dd>" + safe_value + "</dd></div>"

    fields = "".join((
        field("Bestanden in het pakket", report["installed_software_file_count"]),
        field("Vastgelegde originele bronnen", report["pinned_original_file_count"]),
        field("Vergeleken met lokale broncode", report["checkout_verified_file_count"]),
        field("SHA-256 van software-ZIP", report["software_archive_sha256_unsigned"], code=True),
        field("SHA-256 van pakketlijst", report["manifest_sha256_unsigned"], code=True),
    ))
    # Static local HTML: no JavaScript, remote fonts, tracking, network or
    # embedded source names. The source-bound JSON stays fully machine readable.
    page = ("""<!doctype html><html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; style-src 'unsafe-inline'; object-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp | Integriteitsrapport</title>
<style>
*{box-sizing:border-box}body{font:16px/1.55 system-ui,-apple-system,sans-serif;color:#202726;background:#f5f5f2;margin:0}
main{max-width:740px;margin:5vh auto;padding:40px;background:#fff;border:1px solid #dadeda;border-radius:12px}
.eyebrow{font-size:12px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:#52625b}
h1{font-size:clamp(28px,5vw,38px);line-height:1.12;letter-spacing:-.04em;margin:12px 0}
.intro{font-size:17px;color:#3e4944;max-width:56ch;margin:0 0 30px}
dl{margin:0}.field{padding:14px 0;border-top:1px solid #e3e7e3}dt{font-size:13px;color:#53625b;margin-bottom:4px}
dd{font-weight:600;margin:0;overflow-wrap:anywhere}code{font:12px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;font-weight:500;word-break:break-all}
h2{font-size:18px;letter-spacing:-.015em;margin:0 0 8px}
.notice{border-top:2px solid #202726;margin-top:30px;padding-top:22px}
.notice p{margin:0;color:#3e4944}footer{color:#69736d;font-size:12px;margin-top:24px}
@media(max-width:760px){main{margin:0;border:0;border-radius:0;min-height:100vh;padding:24px 20px}}
</style></head><body><main>
<div class="eyebrow">LightUp / Alleen lokaal</div>
<h1>Integriteitsrapport</h1>
<p class="intro">Het softwarepakket komt overeen met de bronbestanden in deze lokale checkout. De gecontroleerde bestandsgegevens staan hieronder.</p>
<dl>""" + fields + """</dl>
<section class="notice"><h2>Geen vrijgave</h2>
<p>Dit rapport bewijst niet wie het pakket heeft gemaakt, of er toestemming is, of een kwetsbaarheid is hersteld. Voor gebruik zijn afzonderlijke autorisatie en onafhankelijke beoordeling vereist.</p></section>
<footer>Alleen voor menselijke controle · Niet ondertekend · Niet geschikt als bewijs van toestemming</footer>
</main></body></html>""")
    return canonical(report), page.encode("utf-8")

def publish_integrity_receipt(folder: Path, output: Path, receipt: dict,
                              verified: dict[str, bytes], checkout_compared: bool) -> None:
    """Create a separate private reproducibility passport, never a consent receipt."""
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose an unused literal absolute private report directory")
    owner_dir(output.parent)
    require(output != ROOT and ROOT not in output.parents
            and output != folder and folder not in output.parents
            and output not in folder.parents
            and output not in ROOT.parents,
            "Integrity report must remain outside source checkout and installed suite")
    report_json, report_html = passport_material(receipt, verified, checkout_compared)
    stage, stage_identity = create_private_stage(output.parent, ".lightup-integrity-")
    try:
        write_file(stage / "REVIEW_ONLY.json", report_json)
        write_file(stage / "REVIEW_ONLY.html", report_html)
        require(not output.exists() and not output.is_symlink(),
                "Private report destination appeared during publication")
        exclusive_publish(stage, output, expected_identity=stage_identity)
    finally:
        cleanup_private_stage(stage, stage_identity)
    print("PRIVATE reproducibility passport:", output)
    print("Unsigned digests do not establish authenticity, consent or release.")


def reopen_integrity_receipt(folder: Path, report_dir: Path,
                             receipt: dict, verified: dict[str, bytes],
                             checkout_compared: bool) -> None:
    """Re-admit a previously produced PRIVATE source-only passport.

    Require an original installed package and independently reconstruct both
    native JSON and scriptless HTML. This is local reproducibility, not a
    signature, producer identity, authority or authenticated chronology.
    """
    require(report_dir.is_absolute() and
            report_dir.parent == report_dir.parent.resolve(strict=True)
            and report_dir != folder and report_dir not in folder.parents
            and folder not in report_dir.parents
            and report_dir != ROOT and ROOT not in report_dir.parents
            and report_dir not in ROOT.parents,
            "PRIVATE passport must be separate from checkout and installed suite")
    owner_dir(report_dir)
    require({p.name for p in report_dir.iterdir()} ==
            {"REVIEW_ONLY.json", "REVIEW_ONLY.html"},
            "PRIVATE passport contains missing or extra entries")
    json_bytes = read_owner_file(report_dir / "REVIEW_ONLY.json", ceiling=350_000)
    html_bytes = read_owner_file(report_dir / "REVIEW_ONLY.html", ceiling=350_000)
    expected_json, expected_html = passport_material(receipt, verified, checkout_compared)
    require(json_bytes == expected_json and html_bytes == expected_html,
            "Passport differs from original installed software or native renderer")
    print("REVIEW_ONLY: original private software passport reopened and byte-matched.")
    print("A matched unsigned passport is not source authentication or consent.")


def verify(folder: Path, *, compare_checkout: bool = False,
           report_dir: Path | None = None,
           passport_dir: Path | None = None) -> None:
    # A reproducibility passport must never be issuable (or re-admitted)
    # from self-consistent but checkout-unverified package files.
    # Reject ambiguous operator intent before any possible publication.
    require(not (report_dir is not None and passport_dir is not None),
            "Choose passport publication OR existing passport admission")
    require((report_dir is None and passport_dir is None) or compare_checkout,
            "Reproducibility passport requires explicit --compare-checkout")
    owner_dir(folder)
    receipt = parse(read_owner_file(folder / "manifest.json", ceiling=350_000))
    require(set(receipt) == {"kind", "version", "disposition", "authority_granted",
                            "scan_authorized", "verified_remediation", "client_consent",
                            "source_heads", "files", "warning"}
            and receipt["kind"] == KIND and type(receipt["version"]) is int
            and receipt["version"] == 1 and receipt["disposition"] == "HUMAN_ONLY_DRAFT_HOLD"
            and all(receipt[k] is False for k in
                    ("authority_granted", "scan_authorized", "verified_remediation", "client_consent"))
            and receipt["warning"] == WARNING, "Not a canonical HUMAN-only suite")
    # A locally consistent archive is not complete merely because every
    # *listed* hash matches: the publisher/recipient's exact fixed inventory
    # must also be present. Do not trust a received manifest to enumerate
    # which original and integrated tools are mandatory.
    _, pinned_lock = catalog()
    files = receipt["files"]
    expected_software = (set(pinned_lock["files"]) | set(INTEGRATED_TOOLS) |
                         {"index.html", "operator.html", "source-lock.json",
                          "software-only.zip"})
    require(type(files) is dict and set(files) == expected_software,
            "Missing or unexpected original/integrated offline software")
    require(receipt["source_heads"] == pinned_lock["source_heads"],
            "Source snapshot identities do not match installed review")
    expected = set(files) | {"manifest.json"}
    # An otherwise empty injected directory is still an unexpected change to
    # the private installed tree. Derive every valid ancestor directory from
    # the canonical mandatory software paths rather than trusting disk layout.
    expected_dirs = {"."}
    for name in expected:
        expected_dirs.update(str(parent) for parent in PurePosixPath(name).parents)
    present = set()
    present_dirs = set()
    for directory, dirnames, filenames in os.walk(folder, followlinks=False):
        current = Path(directory)
        relative = current.relative_to(folder).as_posix()
        # Refuse alien paths BEFORE os.walk can traverse an arbitrarily deep
        # untrusted private directory tree. All approved paths come from the
        # fixed original mandatory software list, never a package manifest.
        require(relative in expected_dirs, "Unexpected software directory")
        owner_dir(current)
        present_dirs.add(relative)
        for dirname in dirnames:
            child = current / dirname
            require(not child.is_symlink() and
                    child.relative_to(folder).as_posix() in expected_dirs,
                    "Unexpected or linked software directory")
        for filename in filenames:
            name = (current / filename).relative_to(folder).as_posix()
            require(name in expected, "Unexpected software file")
            present.add(name)
    require(present == expected and present_dirs == expected_dirs,
            "Package files or directories missing or extra")
    verified = {}
    for name, descriptor in files.items():
        require(safe_name(name) or name in INTEGRATED_TOOLS
                or name in ("index.html", "operator.html", "software-only.zip",
                            "source-lock.json"), "Unexpected package name")
        require(type(descriptor) is dict and set(descriptor) == {"sha256", "bytes"}
                and type(descriptor["bytes"]) is int and descriptor["bytes"] >= 0
                and type(descriptor["sha256"]) is str and len(descriptor["sha256"]) == 64,
                "Invalid package descriptor")
        raw = read_owner_file(folder / name, ceiling=MAX_TOTAL if name == "software-only.zip" else MAX_SOURCE)
        require(digest(raw) == descriptor["sha256"] and len(raw) == descriptor["bytes"],
                "Package file bytes changed")
        verified[name] = raw
    require(verified["index.html"] == home(), "Launcher differs from pinned local renderer")
    import operator_console
    require(verified["operator.html"] == operator_console.render(),
            "Operator studio differs from original native offline renderer")
    installed_lock = parse(verified["source-lock.json"])
    require(installed_lock == pinned_lock, "Source inventory changed")
    for name, descriptor in installed_lock["files"].items():
        require(name in verified and digest(verified[name]) == descriptor["sha256"],
                "Installed source not pinned")
    # The original lock pins source-owner files, not the integration's own
    # operator CLIs and browsers. A self-consistent manifest/ZIP alone is not
    # sufficient for those executable tools. Re-admit all 25 against the
    # current explicit trusted code even in the ordinary inspect operation;
    # --compare-checkout additionally checks every pinned original source.
    for name in INTEGRATED_TOOLS:
        require(verified[name] == read_checkout_source(ROOT / name),
                "Integrated software differs from the trusted local checkout")
    print(f"LOCAL TOOL PARITY: {len(INTEGRATED_TOOLS)} installed integrated tools match local checkout bytes.")
    print("Local tool parity does not prove producer identity or independent review.")
    # Admit the literal full ZIP layout as well as uncompressed payloads:
    # no prepended stub, trailing records or contradictory local headers.
    # Inspect already-admitted owner-private bytes, not a reopened pathname.
    archive_files = unpack_native_archive(
        verified["software-only.zip"], set(verified) - {"software-only.zip"})
    require(all(data == verified[name] for name, data in archive_files.items()),
            "Archive does not match installed source")
    if compare_checkout:
        require(read_checkout_source(LOCK, 350_000) == verified["source-lock.json"],
                "Local checkout source lock differs from installed suite")
        compared = 0
        for name in sorted(verified):
            if name in ("index.html", "operator.html", "source-lock.json",
                        "software-only.zip"):
                continue
            require(read_checkout_source(ROOT / name) == verified[name],
                    "Installed software differs from the explicit checkout")
            compared += 1
        print(f"CHECKOUT PARITY: {compared} original and integrated software files match exact local checkout bytes.")
        print("Checkout parity is not producer identity or independent approval.")
    if report_dir is not None:
        publish_integrity_receipt(folder, report_dir, receipt, verified, compare_checkout)
    if passport_dir is not None:
        reopen_integrity_receipt(folder, passport_dir, receipt, verified, compare_checkout)
    print("REVIEW_ONLY: offline suite and software archive locally consistent.")
    print("Local hashes are not signatures, authenticated consent or release approval.")

def main() -> int:
    parser = argparse.ArgumentParser(description="Install or inspect source-only offline HUMAN workroom")
    sub = parser.add_subparsers(dest="action", required=True)
    p_build = sub.add_parser("build", help="Publish a fresh PRIVATE 0700 software-only offline suite")
    p_build.add_argument("--output-dir", required=True, type=Path)
    p_verify = sub.add_parser("inspect", help="Inspect a locally installed PRIVATE suite without any network")
    p_verify.add_argument("--workspace", required=True, type=Path)
    p_verify.add_argument("--compare-checkout", action="store_true",
                          help="also compare installed software with the exact current local checkout")
    p_verify.add_argument("--report-dir", type=Path,
                          help="optionally write a NEW 0700 private scriptless integrity passport")
    p_verify.add_argument("--passport-dir", type=Path,
                          help="re-open EXISTING private integrity passport against original software")
    p_preview = sub.add_parser("inspect-archive",
                               help="Validate a PRIVATE software-only ZIP without extraction or writes")
    p_preview.add_argument("--archive", required=True, type=Path)
    p_preview.add_argument("--expected-sha256-file", type=Path,
                           help="optional separate owner-private 0600 original SHA-256+LF fingerprint")
    p_preview.add_argument("--planned-output-dir", type=Path,
                           help="optional read-only validation of a fresh PRIVATE receiver destination")
    p_preview.add_argument("--planned-checksum-file", type=Path,
                           help="optional no-write validation of a fresh PRIVATE checksum file")
    p_hash = sub.add_parser("fingerprint-archive",
                            help="Write a NEW private 0600 SHA-256 file for an admitted source-only ZIP")
    p_hash.add_argument("--archive", required=True, type=Path)
    p_hash.add_argument("--output-file", required=True, type=Path)
    p_recv = sub.add_parser("receive", help="Safely reconstruct pinned software-only ZIP offline")
    p_recv.add_argument("--archive", required=True, type=Path)
    p_recv.add_argument("--output-dir", required=True, type=Path)
    p_recv.add_argument("--expected-sha256-file", type=Path,
                        help="optional separate owner-private 0600 original SHA-256+LF fingerprint")
    args = parser.parse_args()
    try:
        for original_arg in vars(args).values():
            if isinstance(original_arg, Path):
                require_operator_path(original_arg)
        if args.action == "build":
            build(args.output_dir)
        elif args.action == "receive":
            from receiver import receive
            receive(args.archive, args.output_dir, args.expected_sha256_file)
        elif args.action == "inspect-archive":
            from receiver import inspect_archive
            inspect_archive(args.archive, args.expected_sha256_file,
                            args.planned_output_dir, args.planned_checksum_file)
        elif args.action == "fingerprint-archive":
            from receiver import fingerprint_archive
            fingerprint_archive(args.archive, args.output_file)
        else:
            verify(args.workspace, compare_checkout=args.compare_checkout,
                   report_dir=args.report_dir, passport_dir=args.passport_dir)
        return 2  # REVIEW_ONLY; not a release success signal.
    except (Hold, OSError, KeyError, TypeError, zipfile.BadZipFile, ValueError) as exc:
        print("HOLD:", str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
