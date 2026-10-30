"""Exclusive, source-bound offline workroom for one original HUMAN HOLD pair.

This is an unsigned local consistency packet, never an approval, a source
authentication, a remediation verdict or permission to contact targets.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .lab_score_action_focus import render_action_focus
from .lab_score_action_batch import render_human_batch
from .lab_score_review_actions import build_review_actions
from .lab_score_review_delta import compare_portable_review_transports
from .lab_score_queue_workroom import _check_file
from .lab_score_inspect import _private_dir_fd
from .lab_score_suite import _private_output_directory

_FORMATS = (
    ("actions-focus-json", "focus.json"),
    ("actions-focus-text", "focus.txt"),
    ("actions-focus-html", "focus.html"),
)


def _canonical(first: str, second: str, selector: tuple[str, str, str]) -> tuple[dict, dict[str, bytes]]:
    comparison = compare_portable_review_transports(first, second)
    actions = build_review_actions(comparison, first, second)
    is_batch = type(selector) is str
    if is_batch:
        formats = (("actions-batch-json", "batch.json"),
                   ("actions-batch-markdown", "batch.md"),
                   ("actions-batch-html", "batch.html"))
        payloads = {name: render_human_batch(actions, selector, fmt).encode("utf-8")
                    for fmt, name in formats}
    else:
        if type(selector) is not tuple or len(selector) != 3:
            raise ValueError("invalid original HUMAN focus selection")
        payloads = {name: render_action_focus(actions, *selector, fmt).encode("utf-8")
                    for fmt, name in _FORMATS}
    receipt = {
        "schema": ("lightup.lab-score-original-human-batch-room.v1" if is_batch
                   else "lightup.lab-score-original-human-focus-room.v1"),
        "selector": selector if is_batch else list(selector),
        "global_review_status": "HOLD",
        "original_unsigned_transport_sha256": {
            source: comparison[source]["unsigned_transport_sha256"]
            for source in ("baseline", "candidate")
        },
        "file_sha256": {name: hashlib.sha256(data).hexdigest()
                        for name, data in payloads.items()},
        "unsigned_local_consistency_only": True,
        "source_authenticated": False,
        "authorization_granted": False,
        "remediation_verified": False,
        "deployment": False,
        "mandatory_human_review": True,
    }
    payloads["manifest.json"] = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    if any(not 0 < len(data) <= 65536 for data in payloads.values()):
        raise ValueError("oversized source-local HUMAN workroom")
    return comparison, payloads


def _paths(first: str, second: str, directory: str) -> Path:
    if any(".." in Path(p).parts for p in (first, second, directory)):
        raise ValueError("parent traversal rejected")
    sources = [Path(os.path.abspath(Path(p).expanduser())) for p in (first, second)]
    target = Path(os.path.abspath(Path(directory).expanduser()))
    for source in sources:
        # An alias can defeat lexical source/workroom overlap checks and can
        # be redirected after the original ZIP has been inspected. Keep the
        # private packet bound to direct, non-symlink original source paths.
        if Path(os.path.realpath(source)) != source:
            raise ValueError("symbolic original ZIP source path rejected")
        if (target == source or target == source.parent
                or target in source.parents or source in target.parents):
            raise ValueError("HUMAN focus workroom overlaps original evidence")
    return target


def publish_private_focus(first: str, second: str, directory: str,
                          selector: tuple[str, str, str]) -> dict:
    """Publish four private files atomically; never overwrite a prior room."""
    target = _paths(first, second, directory)
    comparison, payloads = _canonical(first, second, selector)
    root = _private_output_directory(target)
    directory_fd = _private_dir_fd(root)
    created: list[tuple[str, tuple[int, int]]] = []
    try:
        try:
            for name, data in payloads.items():
                temp = "." + name + ".tmp"
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
                try:
                    with os.fdopen(fd, "wb") as writer:
                        writer.write(data)
                        writer.flush()
                        os.fsync(writer.fileno())
                    stamp = os.stat(temp, dir_fd=directory_fd, follow_symlinks=False)
                    identity = (stamp.st_dev, stamp.st_ino)
                    os.link(temp, name, src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd, follow_symlinks=False)
                    created.append((name, identity))
                    os.unlink(temp, dir_fd=directory_fd)
                    if _check_file(directory_fd, name, data)[:2] != identity:
                        raise ValueError("saved HUMAN focus file replaced")
                finally:
                    try:
                        os.unlink(temp, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
            os.fsync(directory_fd)
            # Original ZIPs must remain byte-identical after the private save.
            if compare_portable_review_transports(first, second) != comparison:
                raise ValueError("original ZIP changed during focus publication")
        except Exception:
            for name, identity in reversed(created):
                try:
                    stamp = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (stamp.st_dev, stamp.st_ino) == identity:
                        os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            try:
                actual = os.stat(root, follow_symlinks=False)
                pinned = os.fstat(directory_fd)
                if (pinned.st_dev, pinned.st_ino) == (actual.st_dev, actual.st_ino) and not os.listdir(directory_fd):
                    os.rmdir(root)
            except OSError:
                pass
            raise
    finally:
        os.close(directory_fd)
    # Reinspect original source and the entire saved room before acknowledging.
    verify_private_focus(first, second, str(root), selector)
    return comparison


def verify_private_focus(first: str, second: str, directory: str,
                         selector: tuple[str, str, str]) -> tuple[dict, dict[str, bytes]]:
    """Source re-derive all four stored files, read twice, no modification."""
    target = _paths(first, second, directory)
    comparison, expected = _canonical(first, second, selector)
    fd = _private_dir_fd(target)
    try:
        identity: dict[str, tuple] = {}
        for _ in range(2):
            if set(os.listdir(fd)) != set(expected):
                raise ValueError("untrusted source-local HUMAN room inventory")
            for name, data in expected.items():
                current = _check_file(fd, name, data)
                if name in identity and current != identity[name]:
                    raise ValueError("source-local HUMAN room changed between reads")
                identity[name] = current
        if set(os.listdir(fd)) != set(expected):
            raise ValueError("source-local HUMAN room inventory changed")
    finally:
        os.close(fd)
    if compare_portable_review_transports(first, second) != comparison:
        raise ValueError("original ZIP changed during source-local HUMAN reinspection")
    return comparison, expected
