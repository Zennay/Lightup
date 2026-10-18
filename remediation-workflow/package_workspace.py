#!/usr/bin/env python3
"""Build a deterministic, strictly source-pinned offline remediation workspace ZIP."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "remediation-workflow" / "LightUp-Remediation-Workspace.zip"

# Immutable owner artifacts, no original branches or owner source modifications.
CONTENT = {
    "remediation-workflow/standalone.html": "2aa09a2723c4b1ac082cd97edd9ccb068ebb440c76f442e4f6e4c07d81e13dfb",
    "remediation-evidence/standalone.html": "a818110f7078aa8a9981ea9857cc898221cd01b9b7490493a8945357d0ee967f",
    "remediation-evidence/team-reply-standalone.html": "9bcc56688e3f56336f0ac2e49032d34f04f392e36fff4c1ee620d667ad86c08e",
    "remediation-capacity/standalone.html": "88a8e13ff62915f96a6ef74fccc2fe513e2fc92582a4d48e7fd2cc4fd7ab1659",
    "remediation-funding/standalone.html": "c118071dc2cb5e85ba204113f2f65bcc3e56f419ed9a46b49916477b651f125a",
    "client-brief/standalone.html": "b1ec34b3a8e3be0f078764c73e2232f1a269b22b69623d1aa31486c566393e9c",
}
INDEX = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp offline remediation workspace</title>
<style>body{font:17px/1.55 system-ui;background:#0d1d29;color:#effff8;max-width:860px;margin:5vh auto;padding:24px}a{color:#78edc5;font-weight:bold}li{margin:15px 0}aside{border:1px solid #cfa979;border-radius:12px;padding:18px;background:#362b24}small{color:#bfd9d5}</style>
<h1>LightUp · private remediation coordination</h1>
<aside><strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</strong> No authentication, consent, grant, retest authorization, verified fix, active scan, deployment or security verdict. Only open originally authorized private source exports.</aside>
<h2>Local tools</h2><ol>
<li><a href="remediation-evidence/standalone.html">Evidence Review Board</a> — original findings, private human reference dossiers and unsigned evidence JSON.</li>
<li><a href="remediation-capacity/standalone.html">Capacity Studio</a> — hypothetical week-by-week staffing plans and exact-CSV working draft JSON.</li>
<li><a href="remediation-workflow/standalone.html">Coordination Cockpit</a> — joins original snapshots and private planning drafts, human source revisions, and editable source-bound evidence dossiers without inferring repairs.</li>
<li><a href="remediation-funding/standalone.html">Funding Studio</a> — original aggregate-only staffing budget, cash release and urgent backlog exposure planning.</li>
<li><a href="client-brief/standalone.html">Client Security Brief</a> — source-bound original finding summary, human remediation narrative and private/redacted client handoff.</li>
<li><a href="remediation-evidence/team-reply-standalone.html">Private Team Reply Desk</a> — edit a single-team human reply packet; independently confirm recipients before sharing.</li>
</ol><p><small>No executable target client, data, credentials, permissions, private findings or secrets are included in this distribution. All apps use local in-memory data; outputs are private and manually downloaded. Original source stays unchanged. Original mandatory CI/security/privacy/consent/HUMAN GO gates are not waived.</small></p></html>"""

README = """LightUp · Offline Remediation Workspace
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.

1. Open START-HERE.html locally.
2. Work in Evidence Review Board with a separately authorized original findings CSV.
3. Optionally import those exact original CSV bytes into Capacity Studio.
4. Export private Evidence JSON, optionally original Casework JSON and Capacity draft JSON.
5. Open Coordination Cockpit and select the exact original CSV with those files.
5a. From Cockpit, explicitly export the PRIVATE original CSV for Evidence Review, Capacity Studio or Client Security Brief.
5b. From Cockpit, export aggregate Capacity Studio JSON and import it into Funding Studio to discuss modelled costs.
6. Optional historical original CSV comparison shows added/changed/absent findings.
7. Independently confirm exact same client and engagement. Inspect human coordination.
8. Exports contain unverified local coordination notes, not proof of remediation.

The ZIP contains NO private client data, credentials, evidence, approval, grants,
actions, live scan code, or verified repair outcomes. It has no network runtime.
All release, security, review and consent gates remain HOLD.

Original branches are unchanged: Casework #1568, Evidence Review #1623,
Capacity Studio #1583. Composition remains an isolated draft source candidate.
"""

def zip_entry(zf: zipfile.ZipFile, path: str, data: bytes) -> None:
    info = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, data, compresslevel=9)

def main() -> None:
    payloads = {}
    for relative, digest in CONTENT.items():
        content = (ROOT / relative).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("Immutable source snapshot has changed: " + relative)
        payloads[relative] = content
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        zip_entry(archive, "START-HERE.html", INDEX.encode("utf-8"))
        zip_entry(archive, "README.txt", README.encode("utf-8"))
        for path, contents in sorted(payloads.items()):
            zip_entry(archive, path, contents)
    data = stream.getvalue()
    DEST.write_bytes(data)
    print("Offline coordination workspace ZIP:", len(data), "bytes", hashlib.sha256(data).hexdigest())

if __name__ == "__main__":
    main()
