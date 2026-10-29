#!/usr/bin/env python3
"""Build a PRIVATE, deterministic, fully offline LightUp scope workroom archive.

Package only reviewed pinned companion directories. This builder does not import
LightUp runtime modules or invoke a scanner, web server, network, grant or DB.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import zipfile
from pathlib import Path
from source_pins import verify_snapshot

ROOT = Path(__file__).resolve().parent.parent
HUB = ROOT / "scope-unified-workspace"
SOURCES = (
    ("scope-intake-matrix", "480e4c5e0ff6ffbf020719f0ab3c03c9d1162538", True),
    ("scope-casebook-history", "2e10197061fe7876dcd6458ae4fc70d9674af9d3", False),
    ("scope-casebook-transfer", "f40b0d2cf626e49bbd8f764968df132ba9d4365a", True),
    ("scope-casebook-reconcile", "7de3f5a5549c738eeb90f81c687c9a7d9c7cab3a", True),
    ("authorization-portfolio", "2ac15c5b24bf5646c3749c26fed577209b1b1221", True),
    ("withdrawal-desk", "0235d93fe285edc0cc49ea3aec3580b7dc4e1338", True),
    ("scope-vault", "49a569b2125a80dcaac21655febc07861afa0df2", True),
    ("studio", "71d9e5f760ef2bff46a72b979173bb3181179afb", False),
)
HUB_INPUTS = ("README.md", "hub.template.html", "style.css", "build.py", "check_bundle.py", "verify-local.js", "verify.template.html", "extra-cards.html", "handoff.js", "handoff.template.html", "source-inspector.js", "source-drift.js", "source_pins.py", "PINNED-ORIGINALS.json")
ARCHIVE = HUB / "LightUp-Scope-Offline-DRAFT-HOLD.zip"
MAX_FILE = 8 * 1024 * 1024
MAX_ALL = 30 * 1024 * 1024


def raw(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Missing or unsafe ordinary file: " + str(path))
    if path.stat().st_size > MAX_FILE:
        raise ValueError("Source file exceeds private package limit: " + str(path))
    return path.read_bytes()


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def package():
    verified = verify_snapshot(ROOT, SOURCES)
    print("Pinned original source bytes:", verified, "unchanged files across", len(SOURCES), "workrooms")
    css = raw(HUB / "style.css")
    template = raw(HUB / "hub.template.html").decode("utf-8", "strict")
    if template.count("<!-- EMBED_STYLE -->") != 1 or template.count("CSP_STYLE_HASH") != 1:
        raise ValueError("Ambiguous or missing HTML template markers")
    style_digest = base64.b64encode(hashlib.sha256(css).digest()).decode("ascii")
    if template.count("<!-- EXTRA_CARDS -->") != 1:
        raise ValueError("Missing extra workroom cards slot")
    template = template.replace("<!-- EXTRA_CARDS -->", raw(HUB / "extra-cards.html").decode("utf-8", "strict"))
    html = template.replace("CSP_STYLE_HASH", style_digest).replace(
        "<!-- EMBED_STYLE -->", "<style>" + css.decode("utf-8", "strict") + "</style>"
    )
    result = html.encode("utf-8")
    (HUB / "index.html").write_bytes(result)
    verifier_js = raw(HUB / "verify-local.js")
    verifier_template = raw(HUB / "verify.template.html").decode("utf-8", "strict")
    if any(verifier_template.count(marker) != 1 for marker in (
        "CSP_STYLE_HASH", "CSP_SCRIPT_HASH", "<!-- EMBED_STYLE -->", "<!-- EMBED_SCRIPT -->"
    )):
        raise ValueError("Ambiguous browser verifier source template")
    script_digest = base64.b64encode(hashlib.sha256(verifier_js).digest()).decode("ascii")
    verifier_html = (verifier_template
        .replace("CSP_STYLE_HASH", style_digest)
        .replace("CSP_SCRIPT_HASH", script_digest)
        .replace("<!-- EMBED_STYLE -->", "<style>" + css.decode("utf-8", "strict") + "</style>")
        .replace("<!-- EMBED_SCRIPT -->", "<script>" + verifier_js.decode("utf-8", "strict") + "</script>"))
    (HUB / "verify.html").write_bytes(verifier_html.encode("utf-8"))
    handoff_js = raw(HUB / "source-inspector.js") + b"\n" + raw(HUB / "source-drift.js") + b"\n" + raw(HUB / "handoff.js")
    handoff_template = raw(HUB / "handoff.template.html").decode("utf-8", "strict")
    if any(handoff_template.count(marker) != 1 for marker in (
        "CSP_STYLE_HASH", "CSP_SCRIPT_HASH", "<!-- EMBED_STYLE -->", "<!-- EMBED_SCRIPT -->"
    )):
        raise ValueError("Ambiguous private handoff template")
    handoff_digest = base64.b64encode(hashlib.sha256(handoff_js).digest()).decode("ascii")
    handoff_html = (handoff_template
        .replace("CSP_STYLE_HASH", style_digest)
        .replace("CSP_SCRIPT_HASH", handoff_digest)
        .replace("<!-- EMBED_STYLE -->", "<style>" + css.decode("utf-8", "strict") + "</style>")
        .replace("<!-- EMBED_SCRIPT -->", "<script>" + handoff_js.decode("utf-8", "strict") + "</script>"))
    (HUB / "handoff.html").write_bytes(handoff_html.encode("utf-8"))

    candidates = []
    for dirname, _, standalone in SOURCES:
        directory = ROOT / dirname
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError("Missing or unsafe pinned app folder: " + dirname)
        if standalone:
            raw(directory / "standalone.html")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("Symlink forbidden: " + str(path))
            if path.is_file():
                candidates.append(path)
    for name in HUB_INPUTS:
        candidates.append(HUB / name)
    candidates.append(HUB / "index.html")
    candidates.append(HUB / "verify.html")
    candidates.append(HUB / "handoff.html")

    files = {}
    for path in candidates:
        relative = path.relative_to(ROOT).as_posix()
        if relative in files or ".." in Path(relative).parts or path.is_symlink():
            raise ValueError("Unsafe or duplicate package path: " + relative)
        files[relative] = raw(path)
    if sum(map(len, files.values())) > MAX_ALL:
        raise ValueError("Private archive budget exceeded")

    manifest = {
        "format": "lightup.scope_offline_bundle.v1",
        "posture": "INCUBATE_M3_M7_DRAFT_HOLD",
        "authority": {
            "client_consent": False, "operator_consent": False,
            "grant": False, "scan": False, "deploy": False, "release": False,
        },
        "pinned_original_branch_heads": {
            name: commit for name, commit, _ in SOURCES
        },
        "file_entries": [
            {"path": path, "size": len(files[path]), "sha256": sha(files[path])}
            for path in sorted(files)
        ],
        "note": "Unsigned transport inventory only; no source authenticity, tenant identity, approval or security release.",
    }
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    (HUB / "SOURCE-MANIFEST.json").write_bytes(manifest_data)
    files["scope-unified-workspace/SOURCE-MANIFEST.json"] = manifest_data

    fd, tmp_name = tempfile.mkstemp(prefix=".lightup-scope-bundle-", suffix=".zip", dir=HUB)
    try:
        with os.fdopen(fd, "wb") as handle:
            with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name, blob in sorted(files.items()):
                    info = zipfile.ZipInfo(name, (2026, 10, 20, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, blob, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, ARCHIVE)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    print("Offline hub:", HUB / "index.html", sha(result))
    print("Source inventory:", HUB / "SOURCE-MANIFEST.json", sha(manifest_data))
    print("Portable archive:", ARCHIVE, ARCHIVE.stat().st_size, sha(raw(ARCHIVE)))


if __name__ == "__main__":
    package()
