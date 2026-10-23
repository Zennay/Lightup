#!/usr/bin/env python3
"""Build two offline LightUp human-review applications and a portable operator kit.

Packaging only: no target, model, grant, network, assessment or customer source.
"""
from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

HERE = Path(__file__).resolve().parent
POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'none'; img-src 'none'; font-src 'none'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'"
)
OUTPUTS = (
    ("index.html", "standalone.html", ("app.js", "collaboration.js")),
    ("team-reply.html", "team-reply-standalone.html", ("team-reply.js",)),
)
BUNDLE = "LightUp-Private-Lab-Review-Kit.zip"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_csp(value: str) -> str:
    return "'sha256-" + base64.b64encode(
        hashlib.sha256(value.encode("utf-8")).digest()
    ).decode("ascii") + "'"


def build(name: str, output: str, scripts: tuple[str, ...]) -> bytes:
    index = (HERE / name).read_text(encoding="utf-8")
    css = (HERE / "style.css").read_text(encoding="utf-8")
    javascript = [(path, (HERE / path).read_text(encoding="utf-8"))
                  for path in scripts]
    if "</style" in css.lower() or any("</script" in js.lower() for _, js in javascript):
        raise ValueError("unsafe raw HTML closing token")
    if index.count(POLICY) != 1:
        raise ValueError("original source policy mismatch")
    style_tag = '<link rel="stylesheet" href="style.css">'
    if index.count(style_tag) != 1:
        raise ValueError("original source stylesheet mismatch")
    new_policy = POLICY.replace(
        "script-src 'self'",
        "script-src " + " ".join(hash_csp(js) for _, js in javascript),
    ).replace("style-src 'self'", "style-src " + hash_csp(css))
    index = index.replace(POLICY, new_policy, 1)
    index = index.replace(style_tag, "<style>" + css + "</style>", 1)
    for path, content in javascript:
        tag = f'<script src="{path}" defer></script>'
        if index.count(tag) != 1:
            raise ValueError(f"missing exact source script tag: {path}")
        index = index.replace(tag, "<script>" + content + "</script>", 1)
    raw = index.encode("utf-8")
    (HERE / output).write_bytes(raw)
    print(output, len(raw), digest(raw))
    return raw


def zip_entry(name: str, body: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    info.create_system = 3
    return info, body


def main() -> int:
    artifacts = {out: build(page, out, js)
                 for page, out, js in OUTPUTS}
    artifacts["README.md"] = (HERE / "README.md").read_bytes()
    artifacts["START-HERE.txt"] = (
        "LightUp PRIVATE lab human review kit; INCUBATE M3/M7 DRAFT/HOLD.\n"
        "1. Keep this ZIP private; no source data is bundled.\n"
        "2. Operator opens standalone.html and selects an ORIGINAL existing PRIVATE lab result.\n"
        "3. Operator filters findings, chooses a bounded subset and saves PRIVATE reviewer handoff.\n"
        "3a. Endpoint coverage summarizes only local ordinals and HUMAN planning counts; export is unverified.\n"
        "4. Human recipient opens team-reply-standalone.html and imports PRIVATE handoff.\n"
        "5. Recipient edits human-only fields, previews and exports PRIVATE reply.\n"
        "6. Operator reopens the unchanged original source, imports reply, inspects private diff\n"
        "   and explicitly accepts or rejects. Then save a NEW PRIVATE operator review.\n"
        "7. All file exchange must use a separately approved confidential channel.\n"
        "8. Source hashes/labels are unsigned; none prove identity, consent, security or scope.\n"
        "9. No scripts execute over network; no target, grant, active assessment or deployment.\n"
        "10. Main merge/release requires original CI, security/privacy, real two-party\n"
        "    consent with action-time revocation, #177/#182/#829 and HUMAN GO.\n"
    ).encode("utf-8")
    lines = [
        "UNSIGNED file-integrity digests (NOT source authenticity, consent or authority)",
        *(f"{digest(content)}  {name}" for name, content in sorted(artifacts.items())),
        "",
    ]
    artifacts["HASHES.txt"] = "\n".join(lines).encode("utf-8")
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for filename, content in sorted(artifacts.items()):
            archive.writestr(*zip_entry(filename, content), compress_type=ZIP_DEFLATED,
                             compresslevel=9)
    blob = stream.getvalue()
    (HERE / BUNDLE).write_bytes(blob)
    print(BUNDLE, len(blob), digest(blob))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
