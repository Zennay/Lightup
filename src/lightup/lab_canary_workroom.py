"""Portable source-free M1 HUMAN history workroom, no extraction or network.

Unsigned ZIP digests prove local byte consistency, NOT provenance, operator
identity, consent, assessment authorization, scans, or release permission.
"""
from __future__ import annotations
import hashlib
import html
import json
import os
from pathlib import Path
import stat
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from .lab_canary_handoff import _strict_json
from .lab_canary_history import render_private_canary_history_html
from .lab_canary_history_store import (
    _read_private_history_snapshot, _validate_history, MANIFEST,
)

KIT = "lightup.m1.source-free-private-history-workroom.v1"
MEMBER_FILES = ("history.json", "history.html", "manifest.json")
MAX_REPORTS = 8


def _index(statuses: tuple[str, ...]) -> bytes:
    # Triage HOLD first without relabeling the original anonymous order.
    prioritized = sorted(enumerate(statuses, 1),
                         key=lambda item: (item[1] != "HOLD", item[0]))
    items = "".join(
        "<li><a href='reports/" + f"{i:02d}" + "/history.html'>"
        "Original anonymous review " + str(i) + " — " + html.escape(status) +
        "</a></li>"
        for i, status in prioritized
    )
    global_status = "HOLD" if "HOLD" in statuses else "PASS"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>LightUp synthetic offline HUMAN review</title></head><body>"
        "<main><h1>LightUp synthetic HUMAN review workroom</h1>"
        "<p>OFFLINE SYNTHETIC LOCALHOST ONLY. NOT approval, consent, "
        "source authentication, scanning rights or deployment permission.</p>"
        "<p>Global synthetic review: <strong>" + global_status + "</strong>; "
        "original reviews: " + str(len(statuses)) + "; HOLD: "
        + str(sum(status == "HOLD" for status in statuses)) + ".</p>"
        "<p>HOLD-first priority; original anonymous source ordinals preserved. "
        "A local PASS never clears a global HOLD.</p>"
        "<ol>" + items + "</ol></main></body></html>\n"
    ).encode()


def _admit_files(files: dict[str, bytes]) -> str:
    """Admit original anonymous snapshot using exactly its canonical bytes."""
    if set(files) != set(MEMBER_FILES):
        raise ValueError("invalid original workroom inventory")
    manifest = _strict_json(files["manifest.json"])
    if (type(manifest) is not dict or set(manifest) != {
            "schema", "signed", "source_authenticated", "files"
    } or manifest["schema"] != MANIFEST
            or manifest["signed"] is not False
            or manifest["source_authenticated"] is not False
            or type(manifest["files"]) is not dict
            or set(manifest["files"]) != {"history.json", "history.html"}):
        raise ValueError("invalid private source-free manifest")
    for name, digest in manifest["files"].items():
        if type(digest) is not str or hashlib.sha256(files[name]).hexdigest() != digest:
            raise ValueError("invalid source-free snapshot digest")
    history = _validate_history(_strict_json(files["history.json"]))
    if files["history.html"] != render_private_canary_history_html(history).encode():
        raise ValueError("unsafe or forged operator HTML")
    return history["review_status"]


def _receipt(statuses: tuple[str, ...], transport_sha: str) -> dict:
    return {
        "schema": KIT, "transport_integrity": True,
        "transport_sha256": transport_sha, "reports_checked": len(statuses),
        "review_status": "HOLD" if "HOLD" in statuses else "PASS",
        "anonymous_statuses": list(statuses),
        "source_authenticated": False, "consent_authenticated": False,
        "authorization_granted": False, "external_target_authorized": False,
        "deployment": False, "human_review_only": True,
        "synthetic_loopback_only": True,
    }


def export_private_history_workroom(source_dirs: list[str], output: str) -> dict:
    """Collect 2..8 fully verified distinct original private report snapshots.

    Never re-read a path after its pinned verified bytes were collected.
    """
    if type(source_dirs) is not list or not 2 <= len(source_dirs) <= MAX_REPORTS:
        raise ValueError("expected 2-8 private synthetic history snapshots")
    members: dict[str, bytes] = {}
    statuses = []
    source_identities = set()
    for number, original in enumerate(source_dirs, 1):
        verified, pinned, identity = _read_private_history_snapshot(original)
        if identity in source_identities:
            raise ValueError("same original snapshot selected twice")
        source_identities.add(identity)
        status = _admit_files(pinned)
        if verified["review_status"] != status:
            raise ValueError("source-free snapshot status mismatch")
        statuses.append(status)
        for name, data in pinned.items():
            members[f"reports/{number:02d}/{name}"] = data
    anonymous = tuple(statuses)
    members["index.html"] = _index(anonymous)
    members["README.txt"] = (
        "LightUp M1 SYNTHETIC LOOPBACK ONLY - HUMAN offline review.\n"
        "Status is not independent evidence, consent, source authentication, "
        "scope, security clearance or deployment authorization.\n"
        "All SHA256 manifests are UNSIGNED local byte consistency checks.\n"
        "Open index.html locally without network; no scripts or active content.\n"
    ).encode()
    manifest = {
        "schema": KIT, "signed": False, "source_authenticated": False,
        "authorization_granted": False, "deployment": False,
        "anonymous_statuses": list(anonymous),
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(members.items())},
    }
    members["transport-manifest.json"] = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    target = Path(output).expanduser()
    if ".." in target.parts or target.name in ("", ".", ".."):
        raise ValueError("invalid destination")
    parent = target.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("destination parent not found")
    path = parent / target.name
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
                for name, data in sorted(members.items()):
                    info = ZipInfo(name, date_time=(2026, 10, 30, 0, 0, 0))
                    info.compress_type = ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, data)
            stream.flush()
            os.fsync(stream.fileno())
        return verify_private_history_workroom(str(path))
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def verify_private_history_workroom(path: str) -> dict:
    """Read-only bounded strict ZIP admission, without extraction or execution."""
    original = Path(path).expanduser()
    if ".." in original.parts:
        raise ValueError("workroom traversal")
    descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(descriptor)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o777 != 0o600
                or not 0 < meta.st_size <= 1024 * 1024):
            raise ValueError("invalid private workroom")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) != meta.st_size:
            raise ValueError("workroom file changed during verification")
    finally:
        os.close(descriptor)
    from io import BytesIO
    with ZipFile(BytesIO(raw)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate original ZIP entry")
        header = archive.getinfo("transport-manifest.json")
        if header.file_size > 32768:
            raise ValueError("oversized manifest")
        manifest = _strict_json(archive.read(header))
        if (type(manifest) is not dict or set(manifest) != {
            "schema", "signed", "source_authenticated",
            "authorization_granted", "deployment", "anonymous_statuses", "files"
        } or manifest["schema"] != KIT or any(
            manifest[k] is not False for k in (
                "signed", "source_authenticated", "authorization_granted", "deployment"
            )
        )):
            raise ValueError("invalid workroom authority flags")
        statuses = manifest["anonymous_statuses"]
        if (type(statuses) is not list or not 2 <= len(statuses) <= MAX_REPORTS
                or any(status not in ("PASS", "HOLD") for status in statuses)):
            raise ValueError("invalid anonymous review statuses")
        expected = {
            f"reports/{number:02d}/{name}"
            for number in range(1, len(statuses)+1)
            for name in MEMBER_FILES
        } | {"index.html", "README.txt"}
        if (type(manifest["files"]) is not dict or set(manifest["files"]) != expected
                or set(names) != expected | {"transport-manifest.json"}):
            raise ValueError("unexpected ZIP files or nested source content")
        files = {}
        for info in archive.infolist():
            if (info.file_size <= 0 or info.file_size > 32768
                    or info.compress_size > 32768
                    or info.create_system != 3
                    or info.external_attr >> 16 != stat.S_IFREG | 0o600
                    or info.compress_type != ZIP_DEFLATED):
                raise ValueError("unsafe ZIP file metadata")
            files[info.filename] = archive.read(info)
        for name, digest in manifest["files"].items():
            if (type(digest) is not str
                    or hashlib.sha256(files[name]).hexdigest() != digest):
                raise ValueError("portable digest mismatch")
        actual = []
        for number in range(1, len(statuses)+1):
            originals = {
                name: files[f"reports/{number:02d}/{name}"]
                for name in MEMBER_FILES
            }
            actual.append(_admit_files(originals))
        if statuses != actual or files["index.html"] != _index(tuple(actual)):
            raise ValueError("forged workroom labels or index")
        if b"<script" in files["README.txt"] or b"/home/" in files["README.txt"]:
            raise ValueError("unsafe workroom instructions")
        return _receipt(tuple(actual), hashlib.sha256(raw).hexdigest())
