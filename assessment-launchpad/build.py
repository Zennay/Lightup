#!/usr/bin/env python3
"""Owner-private launch packet for the *existing* held LightUp lab-assess CLI.

This is preparation only. It imports the unchanged original CLI + LabScenario
admission; never dispatches tools, models, scans or network requests.
"""
from __future__ import annotations

import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit

# Exact-original import: run with PYTHONPATH=src from the repository checkout.
from lightup.labrun import _admit_explicit_lab_url
from lightup.labeval import LabScenario

_MAX_ENDPOINTS = 16
_MAX_INPUT = 16_384
_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
_SCHEMA = "lightup.lab_launchpad_preview.v1"


class Hold(Exception):
    """Safe failure without disclosing untrusted endpoint values."""


def _read_regular(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_INPUT:
            raise Hold("invalid local manifest")
        raw = stream.read(_MAX_INPUT + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or before.st_size != after.st_size
                or before.st_ino != after.st_ino or before.st_dev != after.st_dev
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise Hold("unstable local manifest")
    return raw.decode("utf-8")


def admit(endpoints: list[str]) -> tuple[str, ...]:
    if not 1 <= len(endpoints) <= _MAX_ENDPOINTS:
        raise Hold("expect 1–16 explicit isolated lab URLs")
    selected = []
    for value in endpoints:
        # Match the installed source owner's pre-provider URL fence.
        exact = _admit_explicit_lab_url(value)
        url = urlsplit(exact)
        # Only literal address forms; never DNS resolution, even for lab hosts.
        address = ipaddress.ip_address(url.hostname or "")
        if address.version == 4 and str(address) != url.hostname:
            raise Hold("noncanonical IP address")
        if address.version == 6 and (not url.netloc.startswith("[")
                                      or "%" in url.netloc):
            raise Hold("unsupported IPv6 literal")
        selected.append(exact)
    if len(set(selected)) != len(selected):
        raise Hold("duplicate endpoint")
    # Preserve mandatory original scope isolation / target policy.
    LabScenario(
        scenario_id="launchpad-human-draft",
        name="Unexecuted operator-prepared lab batch",
        targets=tuple(selected),
    )
    return tuple(selected)


def _safe_write(dir_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # This newly created file is not yet in build()'s complete-file list.
        # Remove its partial bytes first so the outer directory cleanup works.
        try:
            os.unlink(name, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def _html(endpoints: tuple[str, ...], digest: str) -> bytes:
    rows = "".join(
        "<tr><th scope='row'>Endpoint %s</th><td><code>%s</code></td></tr>"
        % (i, escape(url, quote=True))
        for i, url in enumerate(endpoints, 1)
    )
    # Entirely scriptless: safe to open directly from disk, no external assets.
    document = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp / Private Lab Launchpad</title><style>
:root{font:16px/1.55 system-ui,sans-serif;color:#e5f2fc;background:#0b1421}
body{max-width:1000px;margin:auto;padding:32px 20px}
header,section{padding:25px;margin-bottom:20px;border:1px solid #355469;border-radius:20px;background:#132739}
h1{margin:0 0 8px;font-size:2.2rem}h2{margin:0 0 14px}
p,small{color:#bed3e1}b{color:#9fe4d8}
table{width:100%;border-collapse:collapse;word-break:break-all}
th,td{text-align:left;padding:12px;border-bottom:1px solid #375061}
th{white-space:nowrap}code,pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#d9f4b4}
aside{padding:14px;border:1px solid #a78158;border-radius:12px}
</style></head><body><header>
<p>LIGHTUP / HUMAN LAB PLAN / OWNER-PRIVATE</p>
<h1>Prepared isolated lab batch</h1>
<p><b>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED</b></p>
<p>__COUNT__ original-policy-admitted literal lab endpoints. No evaluation or
provider contact was performed. This local file includes private endpoints:
do not send it to recipients without independent human confidentiality review.</p>
</header><section><h2>Proposed endpoints</h2><table>
<thead><tr><th>Local slot</th><th>Private lab URL</th></tr></thead>
<tbody>__ROWS__</tbody></table></section>
<section><h2>Optional operator preview — never run by this packet</h2>
<pre>lightup lab-assess --targets-file ./targets.txt --preview-only</pre>
<p>The displayed command refers to the original held lab CLI and its original
scope policy. Preview is no-work, not a security verdict or permission. The
operator must separately validate the original release, environment and
action-time scope/consent before doing anything active.</p>
<p>Original endpoint manifest SHA-256 (private, unsigned): <code>__DIGEST__</code>.</p></section>
<section><aside>Planning does not authenticate asset ownership, validate a
lab fixture, guarantee isolation at later execution, give a customer consent,
prove a finding, bypass an original CI gate or authorize a scan. Missing source
does not mean remediated. Never share this packet as a client security report.</aside>
</section></body></html>""".replace("__COUNT__", str(len(endpoints)))
        .replace("__ROWS__", rows).replace("__DIGEST__", digest))
    start = document.index("<style>") + len("<style>")
    end = document.index("</style>", start)
    style_hash = b64encode(sha256(document[start:end].encode("utf-8")).digest()).decode("ascii")
    document = document.replace("style-src 'unsafe-inline'",
                                "style-src 'sha256-" + style_hash + "'")
    return document.encode("utf-8")


def build(endpoints: tuple[str, ...], output_dir: str) -> Path:
    target = Path(output_dir)
    if target.name in ("", ".", "..") or not target.parent.is_dir():
        raise Hold("invalid output parent")
    # No overwrite or follow of an existing directory, including symlinks.
    os.mkdir(target, 0o700)
    dir_fd = -1
    created: list[str] = []
    try:
        dir_fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
        os.fchmod(dir_fd, 0o700)
        manifest = ("\n".join(endpoints) + "\n").encode("utf-8")
        digest = sha256(manifest).hexdigest()
        packet = {
            "schema": _SCHEMA,
            "status": "DRAFT_HOLD",
            "source_count": len(endpoints),
            "manifest_sha256": digest,
            "source_identity_authenticated": False,
            "preview_only": True,
            "planning_not_permission": True,
            **{key: False for key in _FLAGS},
        }
        artifacts = (
            ("targets.txt", manifest),
            ("private-launchpad.html", _html(endpoints, digest)),
            ("private-plan.json", (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")),
            ("START-HERE.txt", (
                "LIGHTUP / OFFLINE HUMAN LAB LAUNCHPAD / DRAFT-HOLD\n\n"
                "Open private-launchpad.html locally. Keep entire directory owner-private.\n"
                "targets.txt is UTF-8, one original-policy-admitted lab URL per line.\n"
                "Optional operator *no-work* preview, never run by the tool:\n"
                "  lightup lab-assess --targets-file ./targets.txt --preview-only\n\n"
                "The portable browser composer is a convenience, NOT the original scope gate.\n"
                "Any future assessment requires all original independent permissions,\n"
                "action-time revocation checks, CI/security/privacy and HUMAN GO.\n"
                "No completed assessment, grant, scan or verified finding here.\n"
            ).encode("utf-8")),
        )
        for name, content in artifacts:
            _safe_write(dir_fd, name, content)
            created.append(name)
        os.fsync(dir_fd)
    except BaseException:
        # Cleanup is only for files just created in this own exclusive directory.
        if dir_fd >= 0:
            for name in reversed(created):
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except OSError:
                    pass
        try:
            os.rmdir(target)
        except OSError:
            pass
        raise
    finally:
        if dir_fd >= 0:
            os.close(dir_fd)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create owner-private LAB_ONLY batch input; never execute or authorize."
    )
    parser.add_argument("--target", action="append", default=[], metavar="LAB_URL",
                        help="repeat: literal isolated HTTP(S) lab endpoint")
    parser.add_argument("--targets-file", help="optional local UTF-8 original-format endpoint list")
    parser.add_argument("--output-dir", required=True, metavar="NEW_PRIVATE_DIRECTORY")
    args = parser.parse_args(argv)
    try:
        values = list(args.target)
        if args.targets_file is not None:
            values.extend(
                row.strip() for row in _read_regular(args.targets_file).splitlines()
                if row.strip() and not row.lstrip().startswith("#")
            )
        endpoints = admit(values)
        build(endpoints, args.output_dir)
        print("LAB_LAUNCHPAD_PREPARED — PRIVATE DRAFT/HOLD; NO TARGET CONTACT OR AUTHORITY")
        return 2
    except (Hold, OSError, ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, RecursionError):
        print("LAB_LAUNCHPAD_HOLD — original lab inputs or private destination refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
