"""Focused offline contract smoke for the LightUp private receipt tools.

Uses synthetic files only. No network, target access, production data or writes
outside a temporary owner-private directory. HOLD is expected even on success.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import batch
import receipt

AUTHORITY_FALSE = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
BATCH_PRIVATE_FIELDS = {
    "sources_admitted", "total_bytes", "manifest_sha256",
    "ordered_receipt_sha256", "items",
}
SINGLE_SOURCE_FIELDS = {"source_reported_status", "source_sha256", "byte_count"}


def require(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    os.chmod(path, 0o600)


def source_bytes(status: str, extra: dict | None = None) -> bytes:
    source = {"status": status, **{flag: False for flag in AUTHORITY_FALSE}}
    if extra:
        source.update(extra)
    return json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_hold_authority(result: dict, *, batch_result: bool = False) -> None:
    require(result.get("status") == "HOLD", "status must remain HOLD")
    require(result.get("source_authenticated") is False, "source authentication must remain false")
    require(result.get("source_schema_verified") is False, "source schema verification must remain false")
    for flag in AUTHORITY_FALSE:
        require(result.get(flag) is False, f"{flag} must remain false")
    if batch_result:
        require(result.get("manifest_authenticated") is False, "manifest authentication must remain false")


def assert_anonymous_single(result: dict, *, mismatch: bool = False) -> None:
    assert_hold_authority(result)
    require(not (SINGLE_SOURCE_FIELDS & result.keys()), "rejected single source must not disclose metadata")
    if mismatch:
        require(result.get("byte_identity_matches") is False, "digest mismatch must be explicit but anonymous")


def assert_anonymous_batch(result: dict) -> None:
    assert_hold_authority(result, batch_result=True)
    require(result.get("byte_expectations_match") is False, "rejected batch must not claim byte equality")
    require(not (BATCH_PRIVATE_FIELDS & result.keys()), "rejected batch must not disclose partial metadata")


def check_schema_contracts() -> None:
    manifest_schema = json.loads((HERE / "batch-manifest.schema.json").read_text(encoding="utf-8"))
    output_schema = json.loads((HERE / "batch-receipt.schema.json").read_text(encoding="utf-8"))
    require(manifest_schema.get("additionalProperties") is False, "manifest schema must reject extra fields")
    require(manifest_schema["properties"]["format"].get("const") == batch.FORMAT, "manifest schema/runtime version drift")
    sources = manifest_schema["properties"]["sources"]
    require((sources.get("minItems"), sources.get("maxItems")) == (2, 8), "manifest schema must bound batches to 2–8 sources")
    path_pattern = sources["items"]["properties"]["path"].get("pattern")
    require(isinstance(path_pattern, str), "manifest path schema must define a canonical path pattern")
    for path in ("/tmp/first.json", "/var/lib/lightup/lab/source.json"):
        require(re.fullmatch(path_pattern, path) is not None, "manifest schema must accept canonical absolute paths")
    for path in ("/", "//tmp/source.json", "/tmp//source.json", "/tmp/../source.json", "/tmp/./source.json"):
        require(re.fullmatch(path_pattern, path) is None, "manifest schema must reject noncanonical paths")
    require(output_schema.get("additionalProperties") is False, "receipt schema must reject extra fields")
    props = output_schema["properties"]
    require(props["receipt_format"].get("const") == batch.RECEIPT_FORMAT, "receipt schema/runtime version drift")
    require(props["status"].get("const") == "HOLD", "receipt schema must remain HOLD")
    for flag in ("manifest_authenticated", "source_authenticated", "source_schema_verified", *AUTHORITY_FALSE):
        require(props[flag].get("const") is False, f"receipt schema must pin {flag} false")
    require(props["byte_expectations_match"].get("type") == "boolean", "receipt schema must type byte expectation result")


def check_cli(script: Path, *arguments: str) -> dict:
    completed = subprocess.run(
        [sys.executable, str(script), *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    require(completed.returncode == 3, f"{script.name} CLI must exit 3 for HOLD")
    try:
        result = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        raise AssertionError(f"{script.name} CLI must emit one JSON receipt") from None
    require(result.get("status") == "HOLD", f"{script.name} CLI must emit HOLD")
    return result


def run() -> None:
    check_schema_contracts()
    with tempfile.TemporaryDirectory(prefix="lightup-receipt-smoke-") as directory:
        root = Path(directory)
        first = source_bytes("REVIEW_ONLY")
        second = source_bytes("HOLD", {"note": "synthetic-second-source"})
        first_path = root / "first.json"
        second_path = root / "second.json"
        write_private(first_path, first)
        write_private(second_path, second)

        first_digest = digest(first)
        accepted = receipt.inspect(str(first_path), first_digest)
        assert_hold_authority(accepted)
        require(accepted.get("receipt_format") == receipt.RECEIPT_FORMAT, "single receipt format mismatch")
        require(accepted.get("byte_identity_matches") is True, "matching digest must be reported")
        require(accepted.get("source_sha256") == first_digest, "accepted source digest mismatch")
        require(accepted.get("byte_count") == len(first), "accepted source byte count mismatch")
        require(accepted.get("source_reported_status") == "REVIEW_ONLY", "source status must remain unverified metadata")

        wrong_digest = "0" * 64 if first_digest != "0" * 64 else "1" * 64
        mismatch = receipt.inspect(str(first_path), wrong_digest)
        assert_anonymous_single(mismatch, mismatch=True)
        assert_anonymous_single(receipt.inspect(str(first_path), "not-a-digest"))
        assert_anonymous_single(receipt.inspect(os.fsencode(first_path), first_digest))
        assert_anonymous_single(receipt.inspect(str(first_path) + chr(0), first_digest))
        assert_anonymous_single(receipt.inspect(str(first_path) + r"\x00", first_digest))
        assert_anonymous_single(receipt.inspect(f"{root}/../{root.name}/first.json", first_digest))
        assert_anonymous_single(receipt.inspect(str(first_path) + "x" * 4096, first_digest))

        duplicate_key_path = root / "duplicate-key.json"
        duplicate_key = (
            b'{"status":"HOLD","status":"REVIEW_ONLY","authorized":false,'
            b'"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}'
        )
        write_private(duplicate_key_path, duplicate_key)
        assert_anonymous_single(receipt.inspect(str(duplicate_key_path), digest(duplicate_key)))

        authority_path = root / "authority-claim.json"
        authority_claim = source_bytes("REVIEW_ONLY", {"authorized": True})
        write_private(authority_path, authority_claim)
        assert_anonymous_single(receipt.inspect(str(authority_path), digest(authority_claim)))

        permissive_path = root / "permissive.json"
        write_private(permissive_path, first)
        os.chmod(permissive_path, 0o644)
        assert_anonymous_single(receipt.inspect(str(permissive_path), first_digest))

        symlink_path = root / "source-link.json"
        os.symlink(first_path, symlink_path)
        assert_anonymous_single(receipt.inspect(str(symlink_path), first_digest))

        unsafe_dir = root / "unsafe-ancestor"
        unsafe_dir.mkdir()
        os.chmod(unsafe_dir, 0o777)
        unsafe_source_path = unsafe_dir / "source.json"
        write_private(unsafe_source_path, first)
        assert_anonymous_single(receipt.inspect(str(unsafe_source_path), first_digest))

        fifo_path = root / "source.fifo"
        os.mkfifo(fifo_path, 0o600)
        assert_anonymous_single(receipt.inspect(str(fifo_path), first_digest))

        manifest = {
            "format": batch.FORMAT,
            "sources": [
                {"path": str(first_path), "expected_sha256": first_digest},
                {"path": str(second_path), "expected_sha256": digest(second)},
            ],
        }
        manifest_data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest_path = root / "manifest.json"
        write_private(manifest_path, manifest_data)
        manifest_digest = digest(manifest_data)
        assert_anonymous_batch(batch.inspect_batch(os.path.relpath(manifest_path), manifest_digest))

        admitted = batch.inspect_batch(str(manifest_path), manifest_digest)
        assert_hold_authority(admitted, batch_result=True)
        require(admitted.get("receipt_format") == batch.RECEIPT_FORMAT, "batch receipt format mismatch")
        require(admitted.get("byte_expectations_match") is True, "valid batch must match byte expectations")
        require(admitted.get("sources_admitted") == 2, "valid batch must admit both sources")
        require([item.get("ordinal") for item in admitted.get("items", [])] == [1, 2], "batch ordinals must be stable")
        require(admitted.get("total_bytes") == len(first) + len(second), "batch byte total mismatch")
        require(len(admitted.get("ordered_receipt_sha256", "")) == 64, "ordered commitment must be SHA-256")
        repeated = batch.inspect_batch(str(manifest_path), manifest_digest)
        require(repeated.get("ordered_receipt_sha256") == admitted.get("ordered_receipt_sha256"), "same snapshot must be reproducible")

        assert_anonymous_batch(batch.inspect_batch(str(manifest_path), wrong_digest))

        bad_source_manifest = dict(manifest)
        bad_source_manifest["sources"] = [
            dict(manifest["sources"][0]),
            {**manifest["sources"][1], "expected_sha256": wrong_digest},
        ]
        bad_source_data = json.dumps(bad_source_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        bad_source_path = root / "bad-source-manifest.json"
        write_private(bad_source_path, bad_source_data)
        assert_anonymous_batch(batch.inspect_batch(str(bad_source_path), digest(bad_source_data)))

        duplicate_source_path = root / "duplicate-source.json"
        write_private(duplicate_source_path, first)
        duplicate_manifest = {
            "format": batch.FORMAT,
            "sources": [
                {"path": str(first_path), "expected_sha256": first_digest},
                {"path": str(duplicate_source_path), "expected_sha256": first_digest},
            ],
        }
        duplicate_data = json.dumps(duplicate_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        duplicate_manifest_path = root / "duplicate-manifest.json"
        write_private(duplicate_manifest_path, duplicate_data)
        assert_anonymous_batch(batch.inspect_batch(str(duplicate_manifest_path), digest(duplicate_data)))

        cli_single = check_cli(HERE / "receipt.py", str(first_path), first_digest)
        assert_hold_authority(cli_single)
        cli_batch = check_cli(HERE / "batch.py", str(manifest_path), manifest_digest)
        assert_hold_authority(cli_batch, batch_result=True)
        require(cli_batch.get("byte_expectations_match") is True, "valid batch CLI must preserve byte match")

    print("PASS: receipt/batch schemas, deterministic custody, anonymous HOLD failures, CLI exit contract")


if __name__ == "__main__":
    try:
        run()
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:
        print(f"FAIL: unexpected {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1)
