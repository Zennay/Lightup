"""Pure, opt-in byte-exact Git name-status/numstat join oracle for #1541.

Consumes *already collected* synthetic Git `-z` output bytes. Does not run git,
read files, authenticate a repository, grant scope, scan, dispatch or release.
The caller must independently establish provenance. Any ambiguity -> HOLD.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

_MAX_OUTPUT: Final = 262144
_MAX_PATH: Final = 4096
_MAX_FILES: Final = 128
_MAX_COUNT: Final = 1_000_000_000


class PathIdentityHold(ValueError):
    """Generic denial: never echo raw untrusted file names or metadata."""

    def __init__(self):
        super().__init__("HOLD: ambiguous Git path identity")


@dataclass(frozen=True, slots=True)
class CheckedGitPath:
    status: str
    path: str
    previous_path: str | None
    additions: int | None
    deletions: int | None


def _tokens(raw: object) -> list[bytes]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_OUTPUT:
        raise PathIdentityHold()
    if raw[-1] != 0:
        raise PathIdentityHold()
    return raw[:-1].split(b"\0")


def _path(value: bytes) -> str:
    if not value or len(value) > _MAX_PATH:
        raise PathIdentityHold()
    try:
        result = value.decode("utf-8", "strict")
    except UnicodeError:
        raise PathIdentityHold() from None
    if (result.startswith("/") or "\\" in result or
            any(component in ("", ".", "..") for component in result.split("/")) or
            any(ord(c) < 32 or ord(c) == 127 for c in result)):
        # Control characters (including tabs/newlines) are conservatively held:
        # the source-owner must explicitly decide what Git reporting supports.
        raise PathIdentityHold()
    return result


def _count(raw: bytes) -> int | None:
    if raw == b"-":
        return None  # Git's binary-file sentinel.
    if not raw or not raw.isascii() or not raw.isdigit():
        raise PathIdentityHold()
    if len(raw) > 1 and raw.startswith(b"0"):
        raise PathIdentityHold()
    value = int(raw)
    if value > _MAX_COUNT:
        raise PathIdentityHold()
    return value


def _identity_key(value: str) -> str:
    # Reject case/Unicode-normalization aliases conservatively. This is an
    # *advisory* collision fence, not a filesystem identity attestation.
    import unicodedata
    return unicodedata.normalize("NFC", value).casefold()


def _status_code(raw: bytes) -> str:
    if raw in (b"A", b"M", b"D", b"T"):
        return raw.decode("ascii")
    if len(raw) >= 2 and raw[:1] in (b"R", b"C"):
        score = raw[1:]
        if score.isdigit() and 0 <= int(score) <= 100:
            return raw[:1].decode("ascii")
    raise PathIdentityHold()


def parse_git_path_outputs(
    status_zero: bytes,
    numstat_zero: bytes,
) -> tuple[CheckedGitPath, ...]:
    """Join `--name-status -z` with `--numstat -z` by exact decoded identities.

    Both byte streams must be independently authenticated/collected from the
    *same* original and head revisions by the caller. A successful join has no
    authorization or security-verdict significance.
    """
    status = _tokens(status_zero)
    numstat = _tokens(numstat_zero)
    rows: list[tuple[str, str, str | None]] = []
    idx = 0
    while idx < len(status):
        code = _status_code(status[idx])
        idx += 1
        width = 2 if code in ("R", "C") else 1
        if idx + width > len(status):
            raise PathIdentityHold()
        original = _path(status[idx]) if width == 2 else None
        path = _path(status[idx + width - 1])
        idx += width
        rows.append((code, path, original))
        if len(rows) > _MAX_FILES:
            raise PathIdentityHold()

    stats: dict[tuple[str, str | None], tuple[int | None, int | None]] = {}
    idx = 0
    while idx < len(numstat):
        header = numstat[idx].split(b"\t", 2)
        idx += 1
        if len(header) != 3:
            raise PathIdentityHold()
        additions, deletions = _count(header[0]), _count(header[1])
        if header[2] == b"":
            if idx + 2 > len(numstat):
                raise PathIdentityHold()
            previous = _path(numstat[idx])
            path = _path(numstat[idx + 1])
            idx += 2
        else:
            previous, path = None, _path(header[2])
        key = (path, previous)
        if key in stats or len(stats) >= _MAX_FILES:
            raise PathIdentityHold()
        stats[key] = additions, deletions

    if len(rows) != len(stats) or not rows:
        raise PathIdentityHold()
    checked: list[CheckedGitPath] = []
    seen: set[str] = set()
    for code, path, original in rows:
        key = (path, original)
        if key not in stats:
            raise PathIdentityHold()
        for candidate in ((original,) if original is not None else ()) + (path,):
            normalized = _identity_key(candidate)
            if normalized in seen:
                raise PathIdentityHold()
            seen.add(normalized)
        additions, deletions = stats.pop(key)
        checked.append(CheckedGitPath(code, path, original, additions, deletions))
    if stats:
        raise PathIdentityHold()
    return tuple(checked)
