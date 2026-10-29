"""Read-only verifier for persisted synthetic lab replay bundles.

The inspector never starts a fixture, contacts a target, or writes to the bundle.
It emits only aggregate counts and hashes, not evidence payloads or filesystem paths.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Any

from . import lab_replay
from ._lab_bundle_state_verify import verify_state_rows
from .workers import http_baseline

_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_CHECKSUM_BYTES = 128
_MAX_DATABASE_BYTES = 128 * 1024 * 1024
_REQUIRED_FILES = {
    "receipt.json": _MAX_RECEIPT_BYTES,
    "receipt.sha256": _MAX_CHECKSUM_BYTES,
    "state.sqlite3": _MAX_DATABASE_BYTES,
    "domain.sqlite3": _MAX_DATABASE_BYTES,
    "replay-ledger.sqlite3": _MAX_DATABASE_BYTES,
}
_STICKY_TEMP_DIRS = {"/tmp", "/var/tmp", "/dev/shm"}
_HEX_LENGTH = 64


def _canonical(value: Any) -> bytes:
    return lab_replay._canonical(value)


def _sha(payload: bytes) -> str:
    return lab_replay._sha(payload)


def _is_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX_LENGTH
        and all(char in "0123456789abcdef" for char in value)
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _decode_canonical_object(raw: bytes) -> dict[str, Any]:
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise ValueError("JSON object is not canonical")
    return value


def _open_private_bundle(raw_path: str) -> tuple[int, str]:
    if not raw_path or "\x00" in raw_path:
        raise ValueError("invalid bundle path")
    expanded = os.path.expanduser(raw_path)
    if ".." in Path(expanded).parts:
        raise ValueError("ambiguous bundle path")
    absolute = Path(os.path.abspath(expanded))
    parts = absolute.parts
    if len(parts) < 2 or parts[0] != os.sep:
        raise ValueError("invalid bundle path")

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0):
        raise OSError("safe directory open flags are unavailable")

    current_fd = os.open(os.sep, directory_flags)
    try:
        for index, component in enumerate(parts[1:]):
            if component in ("", ".", ".."):
                raise ValueError("ambiguous bundle path")
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            info = os.fstat(current_fd)
            if not stat.S_ISDIR(info.st_mode):
                raise PermissionError("bundle path contains a non-directory")
            candidate = os.path.join(os.sep, *parts[1 : index + 2])
            mode = stat.S_IMODE(info.st_mode)
            final_component = index == len(parts[1:]) - 1
            if final_component:
                if (
                    info.st_uid != os.geteuid()
                    or mode & 0o077
                    or mode & 0o700 != 0o700
                ):
                    raise PermissionError("bundle directory is not owner-private")
            elif mode & 0o022:
                allowed_sticky_tmp = (
                    candidate in _STICKY_TEMP_DIRS
                    and info.st_uid == 0
                    and bool(info.st_mode & stat.S_ISVTX)
                )
                if not allowed_sticky_tmp:
                    raise PermissionError("bundle path has a writable ancestor")
        return current_fd, absolute.name
    except Exception:
        os.close(current_fd)
        raise


def _open_private_file(directory_fd: int, name: str, max_bytes: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or mode & 0o077
            or mode & 0o600 != 0o600
            or info.st_size < 0
            or info.st_size > max_bytes
        ):
            raise PermissionError("bundle file violates private storage contract")
        return fd, info
    except Exception:
        os.close(fd)
        raise


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_fd(fd: int, max_bytes: int, expected_size: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= max_bytes:
        chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) != expected_size or len(data) > max_bytes:
        raise ValueError("bundle file changed or exceeded its bound")
    return bytes(data)


def _assert_file_stable(
    directory_fd: int,
    name: str,
    fd: int,
    original: os.stat_result,
) -> None:
    current = os.fstat(fd)
    linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if _fingerprint(current) != _fingerprint(original):
        raise RuntimeError("bundle file changed during verification")
    if _fingerprint(linked) != _fingerprint(original):
        raise RuntimeError("bundle file identity changed during verification")


def _connect_readonly(fd: int) -> sqlite3.Connection:
    uri = f"file:/proc/self/fd/{fd}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    connection.execute("PRAGMA query_only=ON")
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        connection.close()
        raise ValueError("SQLite integrity check failed")
    return connection


def _verify_receipt(receipt: dict[str, Any], digest: str, bundle_name: str) -> None:
    required = {
        "schema_version",
        "engine_version",
        "fixture_catalog_sha256",
        "profiles",
        "remediation",
        "retests",
        "policy",
        "outcome",
    }
    if set(receipt) != required:
        raise ValueError("receipt schema mismatch")
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != lab_replay.SCHEMA_VERSION
        or receipt["engine_version"] != lab_replay.ENGINE_VERSION
        or not _is_sha(receipt["fixture_catalog_sha256"])
        or bundle_name != digest
    ):
        raise ValueError("receipt identity mismatch")

    expected_policy = {
        "network_scope": "loopback-only",
        "external_target_contacted": False,
        "model_gateway_used": False,
        "live_remediation_performed": False,
        "production_authority_granted": False,
    }
    policy = receipt["policy"]
    if (
        not isinstance(policy, dict)
        or set(policy) != set(expected_policy)
        or policy.get("network_scope") != expected_policy["network_scope"]
        or any(policy.get(key) is not False for key in expected_policy if key != "network_scope")
    ):
        raise ValueError("receipt safety policy mismatch")

    profiles = receipt["profiles"]
    if (
        not isinstance(profiles, list)
        or [item.get("profile_id") for item in profiles if isinstance(item, dict)]
        != list(lab_replay.PROFILE_ORDER)
    ):
        raise ValueError("fixture profile set mismatch")
    for item in profiles:
        if (
            item.get("outcome") not in {"MATCH", "MISMATCH"}
            or not _is_sha(item.get("fixture_sha256"))
            or not _is_sha(item.get("evidence_sha256"))
            or not _is_sha(item.get("event_id"))
            or any(
                not isinstance(item.get(field), list)
                or any(not isinstance(value, str) for value in item[field])
                for field in ("expected_check_ids", "engine_check_ids", "observed_check_ids")
            )
        ):
            raise ValueError("fixture profile receipt is invalid")

    remediation = receipt["remediation"]
    if (
        not isinstance(remediation, dict)
        or remediation.get("kind") != "synthetic_fixture_profile_transition"
        or remediation.get("from_profile") != "exposed"
        or remediation.get("to_profile") != "hardened"
        or remediation.get("state") != "SIMULATED_APPLIED"
        or not _is_sha(remediation.get("event_id"))
        or not isinstance(remediation.get("finding_keys"), list)
    ):
        raise ValueError("synthetic remediation receipt is invalid")

    retests = receipt["retests"]
    if not isinstance(retests, list) or not retests:
        raise ValueError("retest receipt set is empty")
    for item in retests:
        if (
            not isinstance(item, dict)
            or not _is_sha(item.get("finding_key"))
            or not _is_sha(item.get("event_id"))
            or not _is_sha(item.get("baseline_evidence_sha256"))
            or not _is_sha(item.get("retest_evidence_sha256"))
            or not isinstance(item.get("check_id"), str)
            or not isinstance(item.get("stored_retest_status"), str)
            or item.get("outcome") not in {"PASS", "FAIL"}
        ):
            raise ValueError("retest receipt is invalid")

    exposed = profiles[0]
    if any(item["baseline_evidence_sha256"] != exposed["evidence_sha256"] for item in retests):
        raise ValueError("retest baseline binding mismatch")
    if set(remediation["finding_keys"]) != {item["finding_key"] for item in retests}:
        raise ValueError("remediation finding set mismatch")
    expected_outcome = (
        "PASS"
        if all(item["outcome"] == "MATCH" for item in profiles)
        and all(item["outcome"] == "PASS" for item in retests)
        else "FAIL"
    )
    if receipt["outcome"] != expected_outcome:
        raise ValueError("receipt outcome does not match its recorded results")


def _verify_databases(
    database_fds: dict[str, int],
    receipt: dict[str, Any],
) -> tuple[int, int, int, int]:
    with closing(_connect_readonly(database_fds["replay-ledger.sqlite3"])) as ledger:
        receipt_rows = ledger.execute(
            "SELECT receipt_sha256,receipt_json FROM replay_receipts"
        ).fetchall()
        raw_receipt = _canonical(receipt).decode("utf-8")
        digest = _sha(raw_receipt.encode("utf-8"))
        if receipt_rows != [(digest, raw_receipt)]:
            raise ValueError("stored receipt set mismatch")

        events: set[str] = set()
        for event_id, event_type, raw_payload in ledger.execute(
            "SELECT event_id,event_type,payload_json FROM replay_events"
        ):
            payload = _decode_canonical_object(raw_payload.encode("utf-8"))
            expected_id = _sha(_canonical({"event_type": event_type, "payload": payload}))
            if event_id != expected_id or event_id in events:
                raise ValueError("event integrity mismatch")
            events.add(event_id)

        evidence: set[tuple[str, str, str]] = set()
        for evidence_sha, kind, profile_id, raw_payload in ledger.execute(
            "SELECT evidence_sha256,evidence_kind,profile_id,payload_json FROM replay_evidence"
        ):
            payload_bytes = raw_payload.encode("utf-8")
            _decode_canonical_object(payload_bytes)
            if not _is_sha(evidence_sha) or _sha(payload_bytes) != evidence_sha:
                raise ValueError("evidence payload digest mismatch")
            evidence.add((evidence_sha, kind, profile_id))

    profiles = receipt["profiles"]
    retests = receipt["retests"]
    remediation = receipt["remediation"]
    expected_events = (
        {item["event_id"] for item in profiles}
        | {remediation["event_id"]}
        | {item["event_id"] for item in retests}
    )
    if len(expected_events) != len(profiles) + 1 + len(retests) or events != expected_events:
        raise ValueError("event set is not exactly receipt-bound")

    expected_evidence = {
        (item["evidence_sha256"], "baseline", item["profile_id"])
        for item in profiles
    }
    for item in retests:
        expected_evidence.add((item["baseline_evidence_sha256"], "baseline", "exposed"))
        expected_evidence.add((item["retest_evidence_sha256"], "retest", "hardened"))
    if evidence != expected_evidence:
        raise ValueError("evidence set is not exactly receipt-bound")

    profile_by_id = {item["profile_id"]: item for item in profiles}
    retest_by_key = {item["finding_key"]: item for item in retests}
    if len(retest_by_key) != len(retests):
        raise ValueError("duplicate retest finding key")

    with closing(_connect_readonly(database_fds["state.sqlite3"])) as state:
        state_rows = state.execute(
            "SELECT evidence_id,run_id,capability_id,kind,source,sha256,metadata_json FROM evidence"
        ).fetchall()
    baseline_evidence_ids = verify_state_rows(state_rows, profiles, retests)

    with closing(_connect_readonly(database_fds["domain.sqlite3"])) as domain:
        findings = domain.execute(
            "SELECT evidence_ids_json,retest_status FROM findings"
        ).fetchall()
    if len(findings) != len(retests):
        raise ValueError("DomainStore finding count mismatch")
    recorded_statuses = []
    for raw_ids, status in findings:
        evidence_ids = json.loads(raw_ids, object_pairs_hook=_unique_object)
        if (
            not isinstance(evidence_ids, list)
            or not evidence_ids
            or any(not isinstance(item, str) or item not in baseline_evidence_ids for item in evidence_ids)
        ):
            raise ValueError("DomainStore evidence link mismatch")
        recorded_statuses.append(status)
    expected_statuses = [item["stored_retest_status"] for item in retests]
    if sorted(recorded_statuses) != sorted(expected_statuses):
        raise ValueError("DomainStore retest status mismatch")

    return len(events), len(evidence), len(state_rows), len(findings)


def inspect_bundle(raw_path: str) -> dict[str, Any]:
    directory_fd, bundle_name = _open_private_bundle(raw_path)
    file_fds: dict[str, int] = {}
    originals: dict[str, os.stat_result] = {}
    try:
        for name, limit in _REQUIRED_FILES.items():
            fd, info = _open_private_file(directory_fd, name, limit)
            file_fds[name] = fd
            originals[name] = info

        entries = set(os.listdir(directory_fd))
        allowed_entries = set(_REQUIRED_FILES)
        for database_name in ("state.sqlite3", "domain.sqlite3", "replay-ledger.sqlite3"):
            for suffix in ("-wal", "-shm"):
                sidecar = database_name + suffix
                if sidecar not in entries:
                    continue
                sidecar_limit = _MAX_DATABASE_BYTES if suffix == "-wal" else 1024 * 1024
                fd, info = _open_private_file(directory_fd, sidecar, sidecar_limit)
                if suffix == "-wal" and info.st_size != 0:
                    os.close(fd)
                    raise ValueError("SQLite WAL contains uncheckpointed data")
                file_fds[sidecar] = fd
                originals[sidecar] = info
                allowed_entries.add(sidecar)
        if entries != allowed_entries:
            raise ValueError("bundle contains unexpected files")

        receipt_raw = _read_fd(
            file_fds["receipt.json"], _MAX_RECEIPT_BYTES, originals["receipt.json"].st_size
        )
        checksum_raw = _read_fd(
            file_fds["receipt.sha256"], _MAX_CHECKSUM_BYTES, originals["receipt.sha256"].st_size
        )
        receipt = _decode_canonical_object(receipt_raw)
        digest = _sha(receipt_raw)
        if checksum_raw != f"{digest}  receipt.json\n".encode("ascii"):
            raise ValueError("receipt checksum mismatch")
        _verify_receipt(receipt, digest, bundle_name)
        events, evidence, state_rows, finding_rows = _verify_databases(file_fds, receipt)

        for name, fd in file_fds.items():
            _assert_file_stable(directory_fd, name, fd, originals[name])

        return {
            "integrity": "PASS",
            "lab_outcome": receipt["outcome"],
            "receipt_sha256": digest,
            "fixture_catalog_sha256": receipt["fixture_catalog_sha256"],
            "profiles_matched": sum(item["outcome"] == "MATCH" for item in receipt["profiles"]),
            "profiles_total": len(receipt["profiles"]),
            "retests_passed": sum(item["outcome"] == "PASS" for item in receipt["retests"]),
            "retests_total": len(receipt["retests"]),
            "evidence_payloads": evidence,
            "lifecycle_events": events,
            "state_evidence_rows": state_rows,
            "domain_finding_rows": finding_rows,
            "external_target_contacted": False,
            "live_remediation_performed": False,
            "production_authority_granted": False,
        }
    finally:
        for fd in file_fds.values():
            os.close(fd)
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-bundle-inspect",
        description="Read-only integrity verification for a stored synthetic lab replay bundle.",
    )
    parser.add_argument("--bundle-dir", required=True, help="existing private content-addressed bundle")
    args = parser.parse_args(argv)
    try:
        result = inspect_bundle(args.bundle_dir)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "integrity": "FAIL",
                    "error": type(exc).__name__,
                    "message": "bundle verification failed; private paths and evidence details omitted",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
