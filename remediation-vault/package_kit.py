#!/usr/bin/env python3
"""Bundle pinned original LightUp human-only offline apps with the encrypted Handoff Vault.

This is a deterministic static packaging action. No target interaction,
network fetch, permission issuance, QA suite, or source modification.
"""
from pathlib import Path
from hashlib import sha256
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
import json

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "LightUp-Private-Handoff-Vault.zip"
# Immutable original source-owner artifacts: MUST FAIL if upstream bytes change.
# Names are purposefully under own new directory; no active source-owner files edited.
ORIGINALS = {
    "partner-apps/capacity-studio.html": {
        "sha256": "88a8e13ff62915f96a6ef74fccc2fe513e2fc92582a4d48e7fd2cc4fd7ab1659",
        "source_commit": "05d148260a28dd3f09f4ec8161742ff7e0031abe",
        "source_path": "remediation-capacity/standalone.html", "source_owner_pr": 1583,
    },
    "partner-apps/funding-studio.html": {
        "sha256": "c118071dc2cb5e85ba204113f2f65bcc3e56f419ed9a46b49916477b651f125a",
        "source_commit": "b23b87e4797412053b006180239b8206f8708d09",
        "source_path": "remediation-funding/standalone.html", "source_owner_pr": 1586,
    },
    "partner-apps/evidence-review.html": {
        "sha256": "a818110f7078aa8a9981ea9857cc898221cd01b9b7490493a8945357d0ee967f",
        "source_commit": "4494e6a2031900c050af5932d5cd7eb182b3ddf4",
        "source_path": "remediation-evidence/standalone.html",
        "source_owner_pr": 1623,
    },
    "partner-apps/casework-calendar.html": {
        "sha256": "d791d1ad92d29027c3837622117210d023a4bf44f79754eb5da6c150657977e6",
        "source_commit": "ad24da785250556a660f8db1b2bb31af8f129e19",
        "source_path": "remediation-calendar/standalone.html",
        "source_owner_pr": 1635,
    },
    "partner-apps/owner-reply.html": {
        "sha256": "b4d4bb1e1c02f3e0a3ac884e0d5cf05ae0a8a088e97c2ae92a39da9191be742a",
        "source_commit": "ad24da785250556a660f8db1b2bb31af8f129e19",
        "source_path": "remediation-calendar/owner-reply-standalone.html",
        "source_owner_pr": 1635,
    },
    "partner-apps/dependency-board.html": {
        "sha256": "1f769362ac35ea47417ca35227d624fd7ad510591541cd7e2590e7067df1eafa",
        "source_commit": "b04963d367889698927a37fa31128c64f3d9cc0c",
        "source_path": "remediation-dependencies/standalone.html",
        "source_owner_pr": 1638,
    },
}
OWNED = ["START-HERE.html", "standalone.html", "README.md", "WORKFLOWS.md"]
FILES = sorted(set(ORIGINALS).union(OWNED))
data = {}
for path in FILES:
    file = (HERE / path).resolve(strict=True)
    assert file.is_relative_to(HERE.resolve()), "File outside own bundle"
    blob = file.read_bytes()
    assert 0 < len(blob) <= 512 * 1024, "Too-large or empty artifact"
    if path in ORIGINALS:
        assert sha256(blob).hexdigest() == ORIGINALS[path]["sha256"], (
            "Original owner artifact changed: " + path
        )
    data[path] = blob

manifest = {
    "format": "lightup.offline_remediation_kit.v2",
    "stage": "INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD",
    "authority": {
        "verified_client_identity": False,
        "verified_operator_identity": False,
        "consent": False,
        "scan": False,
        "retest": False,
        "remediation_verified": False,
        "deployment": False,
    },
    "privacy": "Package contains ONLY unchanged original standalone app code and generic help; no private data or passwords.",
    "original_source_pins": ORIGINALS,
    "files": [{"path": name, "bytes": len(blob), "sha256": sha256(blob).hexdigest()}
              for name, blob in sorted(data.items())],
}
data["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
    for name, blob in sorted(data.items()):
        meta = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        meta.compress_type = ZIP_DEFLATED
        meta.external_attr = 0o100644 << 16
        archive.writestr(meta, blob, compress_type=ZIP_DEFLATED, compresslevel=9)

binary = OUTPUT.read_bytes()
print("Built", OUTPUT.name, len(binary), "bytes; sha256", sha256(binary).hexdigest())
print("Included original owner snapshots:", len(ORIGINALS))
