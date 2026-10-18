"""Build a deterministic offline-only LightUp operator/team HTML archive.

No source database, network, credentials, STOP writer, scanner or server
component is bundled. This is a HELD human-only offline product artifact.
"""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
FILES = ("README.md", "standalone.html", "team.html")
OUTPUT = ROOT / "LightUp-Incident-Room-Offline-Kit.zip"
PREFIX = "LightUp-Incident-Room/"


def build() -> tuple[str, int]:
    contents: dict[str, bytes] = {}
    for name in FILES:
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required offline product file missing/refused: {name}")
        data = path.read_bytes()
        if not data or len(data) > 200_000 or b"\x00" in data:
            raise ValueError(f"offline product source invalid or too large: {name}")
        contents[name] = data

    manifest = {
        "schema": "lightup.private_offline_incident_kit.v1",
        "status": "INCUBATE_DRAFT_HOLD",
        "artifact_type": "offline_human_only_source_review",
        "files_sha256": {name: sha256(contents[name]).hexdigest() for name in FILES},
        "no_network": True,
        "source_authenticated": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "execution_allowed": False,
        "release_approved": False,
    }
    contents["manifest.json"] = (
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    buffer = BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name in sorted(contents):
            data = contents[name]
            member = zipfile.ZipInfo(PREFIX + name)
            member.date_time = (2026, 10, 18, 0, 0, 0)
            member.create_system = 3
            member.external_attr = (0o100644 << 16)
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    result = buffer.getvalue()
    if len(result) > 120_000:
        raise ValueError("offline distribution exceeded size bound")
    OUTPUT.write_bytes(result)
    return sha256(result).hexdigest(), len(result)


if __name__ == "__main__":
    digest, size = build()
    print("offline human-only DRAFT/HOLD artifact", OUTPUT.name, size, digest)
