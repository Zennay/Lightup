#!/usr/bin/env python3
"""Offline isolated-lab manifest admission and preview handoff. Never executes an assessment."""
from __future__ import annotations

import argparse
import base64
from hashlib import sha1, sha256
from html import escape
import json
import os
from pathlib import Path
import shlex
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PINNED_SOURCE_COMMIT = "74e865201c8a4270e404046ef3447eb7f190edfb"
PINNED_VALIDATOR_BLOBS = {
    "src/lightup/cli.py": "d1053f4360397a94733a78fe7f6b9441b4f126d9",
    "src/lightup/labrun.py": "e2c1a238117783bd0ac1cf3be98b1d1a6444e41c",
    "src/lightup/labeval.py": "ac95f5ad66cf1a53999e2e618152f1a875226dc1",
    "src/lightup/scope.py": "23909917822b5630c76be0cb47c99e1549b30cf8",
    "src/lightup/models.py": "74b96d45a5308d39e2c4c930728e10a2ccc18d2a",
}
MAX_MANIFEST_BYTES = 16_384
MAX_ENDPOINTS = 16
MAX_PINNED_SOURCE_BYTES = 2 * 1024 * 1024
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
STYLE = """body{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#17212f}h1{font-size:1.8rem}.state{border:2px solid #9a5b18;background:#fff7ed;padding:.8rem;font-weight:750}.card{border:1px solid #dbe1e8;border-radius:.5rem;padding:.8rem;margin:.8rem 0}code,pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:.35rem}pre{padding:1rem;border:1px solid #cbd5e1;border-radius:.4rem}.note{font-size:.9rem;color:#536174}li{margin:.35rem 0}@media print{body{margin:0;max-width:none}pre{font-size:9pt}}"""

class Hold(Exception):
    pass

def report_hold(prefix, error=None, explain=False):
    """Report a safe HOLD summary and optionally its curated reason, never raw exception details."""
    print(prefix, file=sys.stderr)
    if explain:
        reason = str(error) if isinstance(error, Hold) else (
            "filesystem, parsing or source-admission error; raw details withheld")
        print("HOLD_REASON: " + reason, file=sys.stderr)

def open_directory_nofollow(path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise Hold("platform lacks required no-follow support")
    absolute = os.path.abspath(os.fspath(path))
    parts = [part for part in absolute.split(os.sep) if part]
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, absolute
    except Exception:
        os.close(fd)
        raise

def open_private_input(path):
    absolute = os.path.abspath(os.fspath(path))
    parent_path, name = os.path.dirname(absolute), os.path.basename(absolute)
    if name in ("", ".", ".."):
        raise Hold("invalid manifest path")
    parent_fd, _ = open_directory_nofollow(parent_path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_MANIFEST_BYTES):
            raise Hold("manifest must be an owner-private bounded regular file")
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(stream.fileno())
        first = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_uid, before.st_mode, before.st_nlink)
        last = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_uid, after.st_mode, after.st_nlink)
        if len(raw) != before.st_size or first != last:
            raise Hold("manifest changed during admission")
    if b"\x00" in raw:
        raise Hold("manifest contains NUL")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise Hold("manifest is not UTF-8") from error
    endpoints = [line.strip() for line in text.splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
    if not 1 <= len(endpoints) <= MAX_ENDPOINTS or len(set(endpoints)) != len(endpoints):
        raise Hold("manifest must contain 1–16 distinct endpoint lines")
    if any(not value or len(value) > 2048 for value in endpoints):
        raise Hold("endpoint length out of range")
    return absolute, raw, endpoints

def git_blob_sha(data):
    return sha1(b"blob " + str(len(data)).encode("ascii") + b"\x00" + data).hexdigest()

def read_stable_pinned_source(path):
    """Read one original source file through no-follow descriptors and reject read-time drift."""
    parent_fd = None
    source_fd = None
    try:
        parent_fd, _ = open_directory_nofollow(path.parent)
        source_fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode)
                or not 0 < before.st_size <= MAX_PINNED_SOURCE_BYTES):
            raise Hold("pinned original validator source is not a bounded regular file")
        content = bytearray()
        with os.fdopen(source_fd, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(min(65_536, MAX_PINNED_SOURCE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > MAX_PINNED_SOURCE_BYTES:
                    raise Hold("pinned original validator source exceeds its size bound")
        after = os.fstat(source_fd)
        identity_before = (
            before.st_dev, before.st_ino, before.st_size, before.st_mode,
            before.st_uid, before.st_gid, before.st_nlink,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev, after.st_ino, after.st_size, after.st_mode,
            after.st_uid, after.st_gid, after.st_nlink,
            after.st_mtime_ns, after.st_ctime_ns,
        )
        if len(content) != before.st_size or identity_before != identity_after:
            raise Hold("pinned original validator source changed during admission")
        return bytes(content)
    except Hold:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise Hold("pinned original validator source could not be admitted") from error
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def load_original_gates():
    for relative, expected in PINNED_VALIDATOR_BLOBS.items():
        actual = git_blob_sha(read_stable_pinned_source(ROOT / relative))
        if actual != expected:
            raise Hold("pinned original validator source drift")
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    try:
        from lightup.labrun import _admit_explicit_lab_url
        from lightup.labeval import LabScenario
        expected_modules = {
            "lightup.labrun": ROOT / "src/lightup/labrun.py",
            "lightup.labeval": ROOT / "src/lightup/labeval.py",
        }
        for name, expected_path in expected_modules.items():
            module = sys.modules.get(name)
            if (module is None or not isinstance(getattr(module, "__file__", None), str)
                    or os.path.abspath(module.__file__) != os.path.abspath(os.fspath(expected_path))):
                raise Hold("pinned original lab validator loaded from an unexpected source path")
        # Re-admit every pinned source after import so ordinary concurrent source
        # changes cannot leave the preview bound only to an earlier file snapshot.
        for relative, expected in PINNED_VALIDATOR_BLOBS.items():
            if git_blob_sha(read_stable_pinned_source(ROOT / relative)) != expected:
                raise Hold("pinned original validator source drifted during import")
    except Hold:
        raise
    except Exception as error:
        raise Hold("pinned original lab validators could not be loaded") from error
    return _admit_explicit_lab_url, LabScenario

def validate_endpoints(endpoints):
    admit_url, lab_scenario = load_original_gates()
    try:
        admitted = [admit_url(value) for value in endpoints]
        if len(set(admitted)) != len(admitted):
            raise Hold("duplicate endpoint")
        lab_scenario(
            scenario_id="offline-launchpad-preview",
            name="Offline isolated lab launchpad preview",
            targets=tuple(admitted),
            expected_findings=None,
        )
    except Exception as error:
        raise Hold("original URL or isolated-lab scope gate rejected the manifest") from error
    return admitted

def open_output_directory(path):
    fd, absolute = open_directory_nofollow(path)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise Hold("output directory must be current-user-owned mode 0700")
    return fd, absolute

def publish_bundle(directory_fd, artifacts):
    created = []
    try:
        for name, data in artifacts:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            created.append(name)
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(directory_fd)
    except Exception:
        for name in reversed(created):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        raise

def render_handoff(endpoint_count, source_digest, normalized_digest, manifest_path, preview_output, command):
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'sha256-" +
        style_hash + "'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp — Isolated Lab Preview Handoff</title><style>" + STYLE + "</style></head><body>"
        "<h1>Isolated-lab manifest handoff</h1>"
        "<p class='state'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · LAB_INPUT_PREVIEW_ONLY · NOT AUTHORIZED</p>"
        "<div class='card'><strong>Endpoint count:</strong> " + str(endpoint_count) +
        "<br><strong>Source manifest SHA-256:</strong> <code>" + escape(source_digest) +
        "</code><br><strong>Canonical manifest SHA-256:</strong> <code>" + escape(normalized_digest) +
        "</code><br><strong>Private manifest path:</strong> <code>" + escape(manifest_path) +
        "</code><br><strong>Future preview output path:</strong> <code>" + escape(preview_output) + "</code></div>"
        "<h2>Exact display-only preview command</h2><pre>" + escape(command) + "</pre>"
        "<p class='note'>The command above was generated for human inspection and has not been run. Its --preview-only flag is mandatory."
        " The original URL syntax and LabScenario scope policy were applied locally without DNS or network access."
        " This handoff does not create a plan, call a model, interact with a target, grant consent or authorize a scan.</p>"
        "<p class='note'>This private HTML omits endpoint values and does not embed the source manifest. Keep the separate manifest, receipt and command in a private directory.</p>"
        "<p class='note'>Not authenticated: source content or identity, client identity, scope approval, operator consent and HUMAN GO. Authorization, consent, dispatch and release flags remain false.</p>"
        "</body></html>"
    )
    return html.encode("utf-8")


def exact_preview_command(directory):
    manifest_path = os.path.join(directory, "lightup-lab-targets.txt")
    preview_output = os.path.join(directory, "lightup-lab-preview-result.json")
    return ("PYTHONPATH=" + shlex.quote(str(SRC)) + " " + shlex.quote(sys.executable) +
            " -m lightup.cli lab-assess --targets-file " + shlex.quote(manifest_path) +
            " --output " + shlex.quote(preview_output) + " --preview-only")


def read_private_bundle_item(directory_fd, name, limit):
    # Bounded stable reads from an existing owner-only receipt bundle; no I/O on targets.
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                 dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= limit):
            raise Hold("existing private output item was not admitted")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        first = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_uid, before.st_mode, before.st_nlink)
        last = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_uid, after.st_mode, after.st_nlink)
        if len(raw) != before.st_size or first != last:
            raise Hold("existing private output item changed while reading")
    return raw


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("duplicate receipt metadata")
        result[key] = value
    return result


def reject_constant(_):
    raise Hold("noncanonical receipt numeric constant")


def verify_existing(directory):
    """Reopen a stored bundle, validate exact bytes and original source pins; never execute."""
    output_fd, absolute = open_output_directory(directory)
    try:
        names = (
            ("lightup-lab-targets.txt", MAX_MANIFEST_BYTES),
            ("lightup-lab-plan-receipt.json", 16_384),
            ("lightup-lab-plan-handoff.html", 65_536),
            ("lightup-lab-preview-command.txt", 16_384),
            ("lightup-lab-minimal-summary.json", 4096),
        )
        if set(os.listdir(output_fd)) != {name for name, _ in names}:
            raise Hold("private Launchpad bundle contains missing or unexpected files")
        items = {name: read_private_bundle_item(output_fd, name, limit)
                 for name, limit in names}
    finally:
        os.close(output_fd)
    receipt = json.loads(items["lightup-lab-plan-receipt.json"].decode("utf-8"),
                         object_pairs_hook=unique_pairs, parse_constant=reject_constant,
                         parse_float=reject_constant)
    if type(receipt) is not dict:
        raise Hold("private receipt is not a JSON object")
    expected_keys = {
        "schema", "status", "source_manifest_sha256", "canonical_manifest_sha256",
        "endpoint_count", "endpoint_slots", "pinned_source_commit",
        "pinned_validator_blob_sha1", "pinned_original_cli_checked",
        "original_url_validator_applied", "original_lab_scenario_scope_policy_applied",
        "endpoint_values_in_receipt", "source_content_authenticated",
        "source_identity_authenticated", "client_identity_authenticated",
        "scope_approval_authenticated", "operator_consent_authenticated",
        "human_go_received", "preview_command_executed", "plan_created",
        "model_called", "target_interaction_performed", "authorization_granted",
        "planning_not_permission", "handoff_html_sha256", "preview_command_sha256",
        *FLAGS,
    }
    if set(receipt) != expected_keys or receipt["schema"] != "lightup.assessment_launchpad_plan_receipt.v1":
        raise Hold("private receipt schema changed")
    if (receipt["status"] != "LAB_INPUT_PREVIEW_ONLY"
            or receipt["pinned_source_commit"] != PINNED_SOURCE_COMMIT
            or receipt["pinned_validator_blob_sha1"] != PINNED_VALIDATOR_BLOBS):
        raise Hold("private receipt's source pin changed")
    for key in FLAGS + ("endpoint_values_in_receipt", "source_content_authenticated",
                        "source_identity_authenticated", "client_identity_authenticated",
                        "scope_approval_authenticated", "operator_consent_authenticated",
                        "human_go_received", "preview_command_executed", "plan_created",
                        "model_called", "target_interaction_performed",
                        "authorization_granted"):
        if receipt[key] is not False:
            raise Hold("private receipt contains non-denying authority claims")
    if (receipt["planning_not_permission"] is not True
            or receipt["pinned_original_cli_checked"] is not True
            or receipt["original_url_validator_applied"] is not True
            or receipt["original_lab_scenario_scope_policy_applied"] is not True):
        raise Hold("missing local non-authorizing source controls")
    for field in ("source_manifest_sha256", "canonical_manifest_sha256",
                  "handoff_html_sha256", "preview_command_sha256"):
        value = receipt[field]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise Hold("invalid unsigned digest in receipt")
    if (sha256(items["lightup-lab-targets.txt"]).hexdigest() != receipt["canonical_manifest_sha256"]
            or sha256(items["lightup-lab-plan-handoff.html"]).hexdigest() != receipt["handoff_html_sha256"]
            or sha256(items["lightup-lab-preview-command.txt"]).hexdigest() != receipt["preview_command_sha256"]):
        raise Hold("stored private bundle contains changed bytes")
    raw_manifest = items["lightup-lab-targets.txt"]
    if b"\x00" in raw_manifest or raw_manifest.startswith(b"\xef\xbb\xbf"):
        raise Hold("stored manifest is not canonical UTF-8")
    decoded = raw_manifest.decode("utf-8")
    endpoints = decoded.splitlines()
    if not 1 <= len(endpoints) <= MAX_ENDPOINTS or decoded != "\n".join(endpoints) + "\n":
        raise Hold("stored manifest has noncanonical structure")
    if (type(receipt["endpoint_count"]) is not int or len(endpoints) != receipt["endpoint_count"]
            or receipt["endpoint_slots"] != list(range(1, len(endpoints) + 1))):
        raise Hold("stored endpoint count or slot inventory changed")
    if validate_endpoints(endpoints) != endpoints:
        raise Hold("pinned original source admission changed")
    if any(type(slot) is not int for slot in receipt["endpoint_slots"]):
        raise Hold("stored slot inventory contains non-integer identifiers")
    expected_summary = (json.dumps(privacy_minimal_summary(len(endpoints)),
                                   indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if items["lightup-lab-minimal-summary.json"] != expected_summary:
        raise Hold("privacy-minimal handoff was modified or extended with source fields")
    command = exact_preview_command(absolute) + "\n"
    if items["lightup-lab-preview-command.txt"] != command.encode("utf-8"):
        raise Hold("private display-only preview command changed")
    # Reconstruct the canonical handoff from the admitted manifest and the
    # original source-bound fixed renderer. A matching self-reported HTML hash
    # alone is not proof that a modified receipt + modified HTML is authentic.
    expected_handoff = render_handoff(
        len(endpoints),
        receipt["source_manifest_sha256"],
        receipt["canonical_manifest_sha256"],
        os.path.join(absolute, "lightup-lab-targets.txt"),
        os.path.join(absolute, "lightup-lab-preview-result.json"),
        command[:-1],
    )
    if items["lightup-lab-plan-handoff.html"] != expected_handoff:
        raise Hold("stored private HTML differs from the pinned canonical preview handoff")
    print("LAB_LAUNCHPAD_RECEIPT_REOPENED endpoint_count=" + str(len(endpoints)) +
          " — UNSIGNED LOCAL BYTE CONSISTENCY ONLY; NOT AUTHORIZED; COMMAND NOT EXECUTED")
    return 0

def privacy_minimal_summary(count):
    """Separate source-free planning counts for explicit low-detail handoff."""
    return {
        "schema": "lightup.assessment_launchpad_minimal_summary.v1",
        "status": "REVIEW_ONLY",
        "source_reported_endpoint_count": count,
        "endpoint_values_embedded": False,
        "source_path_embedded": False,
        "source_hash_embedded": False,
        "customer_or_operator_identity_authenticated": False,
        "original_scope_validator_applied_locally": True,
        "preview_command_executed": False,
        "preview_result_available": False,
        "planning_not_permission": True,
        **{key: False for key in FLAGS},
    }


def run(args):
    source_path, source_raw, endpoints = open_private_input(args.manifest)
    admitted = validate_endpoints(endpoints)
    canonical = ("\n".join(admitted) + "\n").encode("utf-8")
    if len(canonical) > MAX_MANIFEST_BYTES:
        raise Hold("canonical manifest exceeds original CLI limit")
    output_fd, output_dir = open_output_directory(args.output_dir)
    try:
        source_dir = os.path.dirname(source_path)
        common = os.path.commonpath((output_dir, source_dir))
        if common in (output_dir, source_dir):
            raise Hold("output directory must be separate from source manifest directory")
        manifest_path = os.path.join(output_dir, "lightup-lab-targets.txt")
        preview_output = os.path.join(output_dir, "lightup-lab-preview-result.json")
        command = exact_preview_command(output_dir)
        source_digest = sha256(source_raw).hexdigest()
        normalized_digest = sha256(canonical).hexdigest()
        receipt = {
            "schema": "lightup.assessment_launchpad_plan_receipt.v1",
            "status": "LAB_INPUT_PREVIEW_ONLY",
            "source_manifest_sha256": source_digest,
            "canonical_manifest_sha256": normalized_digest,
            "endpoint_count": len(admitted),
            "endpoint_slots": list(range(1, len(admitted) + 1)),
            "pinned_source_commit": PINNED_SOURCE_COMMIT,
            "pinned_validator_blob_sha1": PINNED_VALIDATOR_BLOBS,
            "pinned_original_cli_checked": True,
            "original_url_validator_applied": True,
            "original_lab_scenario_scope_policy_applied": True,
            "endpoint_values_in_receipt": False,
            "source_content_authenticated": False,
            "source_identity_authenticated": False,
            "client_identity_authenticated": False,
            "scope_approval_authenticated": False,
            "operator_consent_authenticated": False,
            "human_go_received": False,
            "preview_command_executed": False,
            "plan_created": False,
            "model_called": False,
            "target_interaction_performed": False,
            "authorization_granted": False,
            "planning_not_permission": True,
            **{key: False for key in FLAGS},
        }
        html_bytes = render_handoff(
            len(admitted), source_digest, normalized_digest, manifest_path, preview_output, command
        )
        receipt["handoff_html_sha256"] = sha256(html_bytes).hexdigest()
        receipt["preview_command_sha256"] = sha256((command + "\n").encode("utf-8")).hexdigest()
        artifacts = [
            ("lightup-lab-targets.txt", canonical),
            ("lightup-lab-plan-receipt.json",
             (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode("utf-8")),
            ("lightup-lab-plan-handoff.html", html_bytes),
            ("lightup-lab-preview-command.txt", (command + "\n").encode("utf-8")),
            ("lightup-lab-minimal-summary.json",
             (json.dumps(privacy_minimal_summary(len(admitted)), indent=2, ensure_ascii=False) +
              "\n").encode("utf-8")),
        ]
        publish_bundle(output_fd, artifacts)
    finally:
        os.close(output_fd)
    print("LAB_LAUNCHPAD_ARTIFACTS_CREATED endpoint_count=" + str(len(admitted)) +
          " — PREVIEW ONLY; NOT AUTHORIZED")
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate a private local lab endpoint manifest and create preview-only artifacts; no assessment is run."
    )
    parser.add_argument("--manifest", help="owner-private local text manifest, mode 0600")
    parser.add_argument("--output-dir", help="existing owner-private output directory, mode 0700")
    parser.add_argument("--verify-output-dir",
                        help="reopen a previously generated private bundle without executing the preview")
    parser.add_argument("--explain-hold", action="store_true",
                        help="print the curated non-sensitive HOLD reason; never prints paths, endpoint values or raw exceptions")
    args = parser.parse_args(argv)
    try:
        if args.verify_output_dir is not None:
            if args.manifest is not None or args.output_dir is not None:
                raise Hold("reopen is exclusive to creation")
            return verify_existing(args.verify_output_dir)
        if args.manifest is None or args.output_dir is None:
            raise Hold("creation needs a manifest and private output directory")
        return run(args)
    except Hold as error:
        report_hold("LAB_LAUNCHPAD_HOLD — private manifest or original lab gate was not admitted",
                    error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, ImportError, UnicodeError,
            OverflowError, RecursionError):
        report_hold("LAB_LAUNCHPAD_HOLD — private manifest or original lab gate was not admitted",
                    None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
