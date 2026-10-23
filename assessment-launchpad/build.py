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
from lightup.lab_catalog import read_selected_lab_design

_MAX_ENDPOINTS = 16
_MAX_INPUT = 16_384
_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
_SCHEMA = "lightup.lab_launchpad_preview.v1"


class Hold(Exception):
    """Safe failure without disclosing untrusted endpoint values."""


def _read_regular_bytes(path: str, bound: int) -> bytes:
    """Descriptor-pinned no-follow read, detecting in-place source revisions."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= bound:
            raise Hold("invalid local source")
        raw = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or before.st_size != after.st_size
                or before.st_ino != after.st_ino or before.st_dev != after.st_dev
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise Hold("unstable local source")
    return raw


def _read_regular(path: str) -> str:
    return _read_regular_bytes(path, _MAX_INPUT).decode("utf-8")


def admit_studio(catalog_file: str, scenario_id: str,
                 endpoints: tuple[str, ...]) -> tuple[dict, bytes]:
    """Reuse the exact original Studio schema and enforce CLI IP/port matching.

    A Studio scenario is a design draft, never trusted ground truth or consent.
    """
    selected = read_selected_lab_design(catalog_file, scenario_id)
    raw = _read_regular_bytes(catalog_file, 262_144)
    if sha256(raw).hexdigest() != selected["catalog_sha256"]:
        raise Hold("Studio file changed during original source admission")
    if len(endpoints) != len(selected["targets"]):
        raise Hold("Studio membership differs from explicit lab endpoints")
    bound_ips = []
    for endpoint in endpoints:
        parsed = urlsplit(endpoint)
        if parsed.port is None:  # Original CLI requires an explicitly declared port.
            raise Hold("Studio endpoints require explicit ports")
        bound_ips.append(str(ipaddress.ip_address(parsed.hostname or "")))
    if len(set(bound_ips)) != len(bound_ips) or set(bound_ips) != set(selected["targets"]):
        raise Hold("Studio declared lab IP set differs from independently entered URLs")
    return selected, raw


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


def _html(endpoints: tuple[str, ...], digest: str, studio: dict | None = None) -> bytes:
    rows = "".join(
        "<tr><th scope='row'>Endpoint %s</th><td><code>%s</code></td></tr>"
        % (i, escape(url, quote=True))
        for i, url in enumerate(endpoints, 1)
    )
    studio_html = ""
    if studio is not None:
        studio_html = ("<aside><h2>Private source-bound Studio draft</h2>"
                       "<p>Selected original scenario: <code>" +
                       escape(studio["scenario_id"], quote=True) +
                       "</code>. Declared expected findings: <code>" +
                       (str(studio["declared_expected_count"]) if
                        studio["declared_expected_count"] is not None else "UNKNOWN") +
                       "</code> — self-declared and never scored ground truth.</p>"
                       "<p>Original catalog SHA-256 (unsigned): <code>" +
                       studio["catalog_sha256"] + "</code>.</p></aside>")
    preview_command = (
        "lightup lab-assess --targets-file ./targets.txt" +
        (" --catalog-file ./studio-catalog.json --scenario-id " +
         studio["scenario_id"] if studio is not None else "") +
        " --preview-only"
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
<pre>__COMMAND__</pre>
__STUDIO_BLOCK__
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
        .replace("__ROWS__", rows).replace("__DIGEST__", digest)
        .replace("__STUDIO_BLOCK__", studio_html)
        .replace("__COMMAND__", escape(preview_command, quote=True)))
    start = document.index("<style>") + len("<style>")
    end = document.index("</style>", start)
    style_hash = b64encode(sha256(document[start:end].encode("utf-8")).digest()).decode("ascii")
    document = document.replace("style-src 'unsafe-inline'",
                                "style-src 'sha256-" + style_hash + "'")
    return document.encode("utf-8")


def build(endpoints: tuple[str, ...], output_dir: str,
          studio: dict | None = None, studio_raw: bytes | None = None) -> Path:
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
            "studio_design_bound": studio is not None,
            "studio_catalog_sha256": studio["catalog_sha256"] if studio else None,
            "studio_scenario_id": studio["scenario_id"] if studio else None,
            "declared_ground_truth_used": False,
            **{key: False for key in _FLAGS},
        }
        artifacts = (
            ("targets.txt", manifest),
            ("private-launchpad.html", _html(endpoints, digest, studio)),
            ("START-HERE.txt", (
                "LIGHTUP / OFFLINE HUMAN LAB LAUNCHPAD / DRAFT-HOLD\n\n"
                "Open private-launchpad.html locally. Keep entire directory owner-private.\n"
                "targets.txt is UTF-8, one original-policy-admitted lab URL per line.\n"
                "Optional operator *no-work* preview, never run by the tool:\n"
                "  lightup lab-assess --targets-file ./targets.txt" +
                (" --catalog-file ./studio-catalog.json --scenario-id " + studio["scenario_id"]
                 if studio else "") + " --preview-only\n\n"
                "The portable browser composer is a convenience, NOT the original scope gate.\n"
                "Any future assessment requires all original independent permissions,\n"
                "action-time revocation checks, CI/security/privacy and HUMAN GO.\n"
                "No completed assessment, grant, scan or verified finding here.\n"
                "Read-only source-bound reopen from the repository (not executed here):\n"
                "  PYTHONPATH=<LightUp_repo>/src python3 "
                "<LightUp_repo>/assessment-launchpad/reopen.py --packet .\n"
                "Unsigned integrity cannot authenticate a source or grant permission.\n"
            ).encode("utf-8")),
        )
        if studio is not None:
            if studio_raw is None or sha256(studio_raw).hexdigest() != studio["catalog_sha256"]:
                raise Hold("missing or changed original Studio source")
            artifacts += (("studio-catalog.json", studio_raw),)
        # Pin every exact private handoff file before publishing the final plan.
        # The unsigned hashes are corruption detection, never producer identity.
        packet["artifact_sha256"] = {
            name: sha256(content).hexdigest() for name, content in artifacts
        }
        artifacts += (("private-plan.json",
                       (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")),)
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
    parser.add_argument("--catalog-file", help="optional original PRIVATE Studio v1 JSON draft")
    parser.add_argument("--scenario-id", help="exact selected Studio scenario ID (paired)")
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
        if (args.catalog_file is None) != (args.scenario_id is None):
            raise Hold("Studio catalog and scenario ID must be supplied together")
        studio, studio_raw = (admit_studio(args.catalog_file, args.scenario_id, endpoints)
                              if args.catalog_file is not None else (None, None))
        build(endpoints, args.output_dir, studio, studio_raw)
        print("LAB_LAUNCHPAD_PREPARED — PRIVATE DRAFT/HOLD; NO TARGET CONTACT OR AUTHORITY")
        return 2
    except (Hold, OSError, ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, RecursionError):
        print("LAB_LAUNCHPAD_HOLD — original lab inputs or private destination refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
