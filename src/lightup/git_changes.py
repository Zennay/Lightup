"""Read-only local git adapter that produces GitHub-compare-shaped file records.

This lets the existing ChangeSet pipeline run on any local checkout (a CI job,
a developer machine) without network access or a GitHub API token. Only
``git diff`` / ``git show`` / ``git rev-parse`` are invoked; the repository
is never modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any

from .changes import ChangeObjectKind
from .github_changes import classify_repository_path
from .structured_changes import StructuredDocumentDelta

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}^~:+-]{0,199}$")
_STATUS = {
    "A": "added", "M": "modified", "D": "removed", "R": "renamed",
    "C": "copied", "T": "changed",
}
_STRUCTURED_SUFFIXES = {
    ChangeObjectKind.API_SPEC: {".json", ".yaml", ".yml"},
    ChangeObjectKind.IAC: {".tf"},
}
_MAX_DOCUMENT_BYTES = 512 * 1024


class GitChangeError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitRange:
    repository: str
    base_revision: str
    head_revision: str
    files: tuple[dict[str, Any], ...]
    structured_deltas: dict[str, StructuredDocumentDelta]


def _validate_ref(ref: str) -> str:
    ref = ref.strip()
    if not _REF.match(ref) or ".." in ref:
        raise GitChangeError(f"unsafe git revision {ref!r}")
    return ref


def _git_bytes(repo: Path, *args: str, check: bool = True) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitChangeError(f"git {args[0]} failed: {exc}") from None
    if check and completed.returncode != 0:
        message = completed.stderr.decode("utf-8", "replace").strip()
        raise GitChangeError(f"git {args[0]} failed: {message[:300]}")
    return completed.stdout


def _git(repo: Path, *args: str, check: bool = True) -> str:
    return _git_bytes(repo, *args, check=check).decode("utf-8", "replace")


def _path(raw: bytes) -> str:
    """Decode one NUL-delimited git path exactly; never substitute bytes."""
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise GitChangeError("changed path is not valid UTF-8; refusing to guess its identity") from None
    if not path:
        raise GitChangeError("git reported an empty changed path")
    return path


def _parse_numstat(output: bytes) -> dict[str, tuple[int | None, int | None]]:
    """Parse ``git diff --numstat -z`` (renames are ``a\tr\t\0old\0new\0``)."""
    tokens = output.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    result: dict[str, tuple[int | None, int | None]] = {}
    index = 0
    while index < len(tokens):
        fields = tokens[index].split(b"\t", 2)
        if len(fields) != 3:
            raise GitChangeError("malformed git numstat record")
        added, removed, name = fields
        if name:
            path, index = _path(name), index + 1
        else:
            if index + 2 >= len(tokens):
                raise GitChangeError("truncated git numstat rename record")
            path, index = _path(tokens[index + 2]), index + 3
        if path in result:
            raise GitChangeError(f"duplicate git numstat path {path!r}")
        result[path] = (
            int(added) if added.isdigit() else None,
            int(removed) if removed.isdigit() else None,
        )
    return result


def _parse_name_status(output: bytes) -> list[tuple[str, str | None, str]]:
    """Parse ``git diff --name-status -z`` into (letter, previous, path)."""
    tokens = output.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    entries: list[tuple[str, str | None, str]] = []
    seen: set[str] = set()
    index = 0
    while index < len(tokens):
        letter = tokens[index][:1].decode("ascii", "replace")
        width = 3 if letter in {"R", "C"} else 2
        if index + width > len(tokens):
            raise GitChangeError("truncated git name-status record")
        previous = _path(tokens[index + 1]) if width == 3 else None
        path = _path(tokens[index + width - 1])
        if path in seen:
            raise GitChangeError(f"duplicate git name-status path {path!r}")
        seen.add(path)
        entries.append((letter, previous, path))
        index += width
    return entries


def _resolve(repo: Path, ref: str) -> str:
    return _git(repo, "rev-parse", "--verify", "--quiet", f"{_validate_ref(ref)}^{{commit}}").strip()


def repository_slug(repo: Path) -> str:
    """Best-effort ``owner/name`` for the checkout, from its origin remote."""
    url = _git(repo, "config", "--get", "remote.origin.url", check=False).strip()
    match = re.search(r"[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url)
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    return f"local/{repo.resolve().name or 'repository'}"


def _show(repo: Path, revision: str, path: str) -> str | None:
    blob = _git(repo, "cat-file", "-s", f"{revision}:{path}", check=False).strip()
    if not blob.isdigit() or int(blob) > _MAX_DOCUMENT_BYTES:
        return None
    return _git(repo, "show", f"{revision}:{path}", check=False)


def collect_git_range(
    repo: str | Path,
    base: str,
    head: str = "HEAD",
    *,
    repository: str | None = None,
    merge_base: bool = True,
) -> GitRange:
    """Collect changed-file records for ``base...head`` from a local checkout.

    With ``merge_base`` (the default) the diff starts at the merge base of the
    two revisions, matching what a pull request would show.
    """
    repo = Path(repo)
    head_sha = _resolve(repo, head)
    base_sha = _resolve(repo, base)
    if not head_sha or not base_sha:
        raise GitChangeError("base or head revision does not exist in this checkout")
    if merge_base:
        merged = _git(repo, "merge-base", base_sha, head_sha, check=False).strip()
        if merged:
            base_sha = merged
    if base_sha == head_sha:
        raise GitChangeError("base and head resolve to the same commit; nothing to review")

    numstat = _parse_numstat(_git_bytes(
        repo, "diff", "--numstat", "-M", "-z", "--no-color", base_sha, head_sha))
    entries = _parse_name_status(_git_bytes(
        repo, "diff", "--name-status", "-M", "-z", "--no-color", base_sha, head_sha))
    if set(numstat) != {path for _letter, _previous, path in entries}:
        raise GitChangeError("git numstat and name-status disagree on the changed paths")
    files: list[dict[str, Any]] = []
    deltas: dict[str, StructuredDocumentDelta] = {}
    for letter, previous, path in entries:
        status = _STATUS.get(letter)
        if status is None:
            continue
        added, removed = numstat[path]
        patch = _git(
            repo, "--literal-pathspecs", "diff", "--no-color", "--no-ext-diff", "-U3", "-M",
            base_sha, head_sha, "--", *(p for p in (previous, path) if p),
        )
        record: dict[str, Any] = {
            "filename": path,
            "status": status,
            "additions": added,
            "deletions": removed,
            "patch": _strip_headers(patch) if patch and added is not None else None,
        }
        if previous is not None:
            record["previous_filename"] = previous
        files.append(record)

        kind = classify_repository_path(path)
        if PurePosixPath(path.lower()).suffix in _STRUCTURED_SUFFIXES.get(kind, set()):
            base_doc = None if status == "added" else _show(repo, base_sha, previous or path)
            head_doc = None if status == "removed" else _show(repo, head_sha, path)
            if base_doc is not None or head_doc is not None:
                deltas[path] = StructuredDocumentDelta(base_doc, head_doc)

    return GitRange(
        repository=repository or repository_slug(repo),
        base_revision=base_sha,
        head_revision=head_sha,
        files=tuple(files),
        structured_deltas=deltas,
    )


def _strip_headers(patch: str) -> str:
    """Keep only hunk content, like the GitHub compare ``patch`` field."""
    lines = patch.splitlines()
    for position, line in enumerate(lines):
        if line.startswith("@@"):
            return "\n".join(lines[position:])
    return ""
