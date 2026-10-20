"""Fail-closed build-time byte pinning of imported original scope companions.

This is a local source snapshot integrity check, not cryptographic provenance,
code review, test evidence, tenant authentication, client consent or authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

DIGEST = re.compile(r"[0-9a-f]{64}\Z")
PIN_LIMIT = 128 * 1024
MAX_ORIGINALS = 32
MAX_SOURCE_FILES = 128
MAX_FILE = 8 * 1024 * 1024


def no_dupes(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate source-pin JSON key")
        result[key] = value
    return result


def verify_snapshot(root: Path, sources: tuple) -> int:
    pins_path = root / "scope-unified-workspace" / "PINNED-ORIGINALS.json"
    if pins_path.is_symlink() or not pins_path.is_file() or pins_path.stat().st_size > PIN_LIMIT:
        raise ValueError("Missing or unsafe pinned-source inventory")
    pins = json.loads(pins_path.read_text("utf-8"), object_pairs_hook=no_dupes)
    if type(pins) is not dict or set(pins) != {"format", "purpose", "heads", "source_files"}:
        raise ValueError("Unexpected pinned-source document")
    if pins["format"] != "lightup.scope_snapshot_pins.v1":
        raise ValueError("Unsupported source-pin format")
    if type(pins["purpose"]) is not str or not pins["purpose"].startswith("unsigned build-time"):
        raise ValueError("Source-pin trust disclaimer missing")
    heads = {name: commit for name, commit, _ in sources}
    if len(heads) != len(sources) or len(heads) > MAX_ORIGINALS or pins["heads"] != heads:
        raise ValueError("Original source HEAD drift")
    source_files = pins["source_files"]
    if type(source_files) is not dict or set(source_files) != set(heads):
        raise ValueError("Original source compartments differ from pinned inventory")
    matched = 0
    for name in heads:
        directory = root / name
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Unsafe original source folder")
        rows = source_files[name]
        if type(rows) is not list or not 1 <= len(rows) <= MAX_SOURCE_FILES:
            raise ValueError("Unbounded original source file set")
        declared = {}
        for item in rows:
            if type(item) is not dict or set(item) != {"path", "size", "sha256"}:
                raise ValueError("Malformed pinned source file")
            path, length, digest = item["path"], item["size"], item["sha256"]
            if type(path) is not str or not path.startswith(name + "/"):
                raise ValueError("Cross-compartment source path")
            parts = Path(path).parts
            if len(parts) < 2 or parts[0] != name or any(part in {"", "..", "."} for part in parts):
                raise ValueError("Malformed original file path")
            if type(length) is not int or not 0 <= length <= MAX_FILE:
                raise ValueError("Unsafe original file size")
            if type(digest) is not str or not DIGEST.fullmatch(digest) or path in declared:
                raise ValueError("Duplicate/invalid original file digest")
            declared[path] = (length, digest)
        actual_paths = []
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError("Symlink added to original source tree")
            if path.is_file():
                actual_paths.append(path.relative_to(root).as_posix())
        if set(actual_paths) != set(declared):
            raise ValueError("Original source files added, removed or renamed")
        for path, (length, digest) in declared.items():
            binary = root / path
            if binary.is_symlink() or not binary.is_file() or binary.stat().st_size != length:
                raise ValueError("Original source size or file type drift")
            with binary.open("rb") as handle:
                content = handle.read(MAX_FILE + 1)
            if len(content) != length or hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Original source file bytes changed from pinned snapshot")
            matched += 1
    return matched
