"""Owner-private, offline M1 safety-canary handoff.

Never transfers source evidence, consent, target scope or execution authority.
The final manifest is written last; only directories containing a matching
manifest may be treated as complete. No network or process launches here.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path

_PASS_KEYS = {
    "status", "passed", "lab_only", "external_target_authorized",
    "deployment_authorized", "public_target_denied", "execution_enabled",
    "scope_refusal_contract_verified", "plan_registry_contract_verified",
    "scorer_evidence_contract_verified", "authentication_required",
    "activation_locked", "forged_session_denied", "csrf_guard_enforced",
    "session_revocation_verified", "cross_tenant_portal_denied",
    "cross_tenant_request_denied", "own_tenant_request_saved",
    "client_operator_route_denied", "cross_origin_request_denied",
    "non_loopback_refused", "fixed_loopback_socket_boundary_enforced",
    "fixed_lab_child_process_policy_enforced", "temporary_state_removed",
    "service_inventory_labeval_passed", "service_inventory_valid_findings",
    "service_inventory_invalid_findings", "service_inventory_missed_findings",
    "service_inventory_reproducibility", "service_inventory_evidence_quality",
    "tls_baseline_labeval_passed", "tls_baseline_valid_findings",
    "tls_baseline_invalid_findings", "tls_baseline_missed_findings",
    "tls_baseline_reproducibility", "tls_baseline_evidence_quality",
    "web_baseline_labeval_passed", "web_baseline_valid_findings",
    "web_baseline_invalid_findings", "web_baseline_missed_findings",
    "web_baseline_reproducibility", "web_baseline_evidence_quality",
}
_HOLD_KEYS = {
    "status", "passed", "lab_only", "external_target_authorized",
    "deployment_authorized", "failure_stage",
}
_HOLD_STAGES = {"setup", "service", "tls", "http"}


def _admit_receipt(result: dict) -> dict:
    """Strict source-free schema; reject future accidental private fields."""
    if type(result) is not dict or result.get("status") not in ("PASS", "HOLD"):
        raise ValueError("invalid offline canary receipt")
    pass_state = result["status"] == "PASS"
    if (result.get("passed") is not pass_state
            or result.get("lab_only") is not True
            or result.get("external_target_authorized") is not False
            or result.get("deployment_authorized") is not False):
        raise ValueError("unsafe canary authority flags")
    if set(result) != (_PASS_KEYS if pass_state else _HOLD_KEYS):
        raise ValueError("unrecognized or incomplete canary fields")
    if not pass_state and result["failure_stage"] not in _HOLD_STAGES:
        raise ValueError("unrecognized failure stage")
    for name, value in result.items():
        if name in ("status", "failure_stage"):
            if type(value) is not str:
                raise ValueError("invalid label")
        elif type(value) is bool:
            continue
        elif type(value) is int and 0 <= value <= 1000000:
            continue
        elif type(value) is float and math.isfinite(value) and 0 <= value <= 1000000:
            continue
        else:
            raise ValueError("invalid or unbounded metric")
    if pass_state:
        for name, value in result.items():
            if name in ("status",):
                continue
            if name.endswith("_findings"):
                if type(value) is not int:
                    raise ValueError("invalid finding count")
            elif name.endswith(("_reproducibility", "_evidence_quality")):
                if type(value) not in (float, int) or not 0 <= value <= 1:
                    raise ValueError("invalid scorer ratio")
            elif type(value) is not bool:
                raise ValueError("invalid canary flag")
        if result["execution_enabled"] is not False:
            raise ValueError("canary execution enabled")
        if any(result[key] is not True for key in _PASS_KEYS
               if key != "status" and key not in (
                   "execution_enabled", "external_target_authorized",
                   "deployment_authorized") and not key.endswith((
                       "_findings", "_reproducibility", "_evidence_quality"))):
            raise ValueError("canary claimed PASS with failed boundary")
    return {
        "schema": "lightup.m1.synthetic-canary-private-handoff.v1",
        "source_authenticated": False,
        "consent_authenticated": False,
        "authorization_granted": False,
        "deployment": False,
        "synthetic_loopback_only": True,
        "canary": result,
    }


def _private_write(directory: Path, name: str, content: bytes) -> None:
    descriptor = os.open(
        directory / name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def save_private_canary_handoff(destination: str, result: dict, summary: str) -> Path:
    """New exclusive 0700 directory, original JSON/text and SHA-bound manifest.

    Does not overwrite existing output, follow final symlinks or expose
    caller paths in exceptions printed by the CLI.
    """
    receipt = _admit_receipt(result)
    # The creator is no exception: an unsafe caller must not publish
    # a manifest-valid offline operator artifact with forged clearance text.
    # This is a pure formatter; no scorer or network call is made here.
    from lightup.lab_canary import _render_text
    if type(summary) is not str or summary != _render_text(result):
        raise ValueError("noncanonical operator summary")
    raw = Path(destination).expanduser()
    if ".." in raw.parts or raw.name in ("", ".", ".."):
        raise ValueError("unsafe private destination")
    parent = raw.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("parent must exist")
    target = parent / raw.name
    json_bytes = (json.dumps(receipt, sort_keys=True, allow_nan=False,
                             separators=(",", ":")) + "\n").encode()
    text_bytes = (summary + "\n").encode()
    files = {"canary.json": json_bytes, "operator.txt": text_bytes}
    manifest = {
        "schema": "lightup.m1.synthetic-canary-private-manifest.v1",
        "manifest_is_authority": False,
        "source_authenticated": False,
        "files": {name: hashlib.sha256(content).hexdigest()
                  for name, content in sorted(files.items())},
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode()
    os.mkdir(target, 0o700)
    try:
        for name, content in sorted(files.items()):
            _private_write(target, name, content)
        # Committed LAST; absent manifest means interrupted/incomplete handoff.
        _private_write(target, "manifest.json", manifest_bytes)
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        # Clean up only files created by this function in its new directory.
        for name in ("canary.json", "operator.txt", "manifest.json"):
            try:
                (target / name).unlink()
            except FileNotFoundError:
                pass
        target.rmdir()
        raise
    return target


def _strict_json(raw: bytes) -> dict:
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def verify_private_canary_handoff(directory: str) -> dict:
    """Read-only descriptor-pinned local integrity, NOT source authentication."""
    import stat

    raw = Path(directory).expanduser()
    if ".." in raw.parts:
        raise ValueError("parent traversal")
    descriptor = os.open(raw, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o777 != 0o700):
            raise ValueError("not owner-private directory")
        filenames = {"canary.json", "operator.txt", "manifest.json"}
        if set(os.listdir(descriptor)) != filenames:
            raise ValueError("private handoff file inventory mismatch")
        files = {}
        for name in sorted(filenames):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                meta = os.fstat(fd)
                if (not stat.S_ISREG(meta.st_mode)
                        or meta.st_uid != os.getuid()
                        or meta.st_mode & 0o777 != 0o600
                        or not 0 < meta.st_size <= 16000):
                    raise ValueError("invalid handoff file")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(16001)
                if len(data) != meta.st_size:
                    raise ValueError("private file changed")
                files[name] = data
            finally:
                os.close(fd)
        manifest = _strict_json(files["manifest.json"])
        if (type(manifest) is not dict
                or set(manifest) != {"schema", "files", "manifest_is_authority",
                                    "source_authenticated"}
                or manifest["schema"] != "lightup.m1.synthetic-canary-private-manifest.v1"
                or manifest["manifest_is_authority"] is not False
                or manifest["source_authenticated"] is not False
                or type(manifest["files"]) is not dict
                or set(manifest["files"]) != {"canary.json", "operator.txt"}):
            raise ValueError("invalid handoff manifest")
        for name, digest in manifest["files"].items():
            if type(digest) is not str or hashlib.sha256(files[name]).hexdigest() != digest:
                raise ValueError("handoff digest mismatch")
        receipt = _strict_json(files["canary.json"])
        if type(receipt) is not dict:
            raise ValueError("invalid handoff receipt")
        result = _admit_receipt(receipt.get("canary"))
        if receipt != result:
            raise ValueError("unsafe handoff receipt")
        summary = files["operator.txt"].decode("utf-8")
        # A rehashed but unsigned manifest cannot admit misleading passive
        # operator instructions. Reconstruct the complete first-party summary
        # byte-for-byte from the strict admitted synthetic canary receipt.
        from lightup.lab_canary import _render_text
        if summary != _render_text(result["canary"]) + "\n":
            raise ValueError("noncanonical private handoff text")
        return {
            "schema": "lightup.m1.synthetic-canary-handoff-verification.v1",
            "transport_integrity": True,
            "synthetic_loopback_only": True,
            "source_authenticated": False,
            "consent_authenticated": False,
            "authorization_granted": False,
            "deployment": False,
            "review_status": result["canary"]["status"],
        }
    finally:
        os.close(descriptor)
