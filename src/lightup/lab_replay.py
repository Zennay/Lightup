"""Deterministic loopback fixture replay with durable evidence lineage.

Only built-in fixtures are used. No target URL is accepted, no model gateway
is loaded, and no external host is contacted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .domain import AccessContext, DomainStore, Role
from .labfixtures import FixtureProfile, PROFILES, expected_findings
from .labrun import run_lab_baseline
from .labsync import ensure_lab_engagement, persist_lab_findings, retest_finding
from .state import StateStore
from .workers import http_baseline

SCHEMA_VERSION = 2
ENGINE_VERSION = "loopback-fixture-replay-v2"
PROFILE_ORDER = ("exposed", "partially-hardened", "hardened")
_LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS replay_events (
 event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replay_evidence (
 evidence_sha256 TEXT NOT NULL, evidence_kind TEXT NOT NULL,
 profile_id TEXT NOT NULL, payload_json TEXT NOT NULL,
 PRIMARY KEY(evidence_sha256,evidence_kind,profile_id)
);
CREATE TABLE IF NOT EXISTS replay_receipts (
 receipt_sha256 TEXT PRIMARY KEY, receipt_json TEXT NOT NULL
);
"""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _profile_payload(profile: FixtureProfile) -> dict[str, Any]:
    return {"profile_id": profile.profile_id, "description": profile.description,
            "headers": [[name, value] for name, value in profile.headers],
            "server_banner": profile.server_banner,
            "expected_check_ids": list(profile.expected_check_ids)}


def _profile_sha(profile: FixtureProfile) -> str:
    return _sha(_canonical(_profile_payload(profile)))


def _catalog_sha() -> str:
    checks = [{"check_id": cid, "title": title, "severity": severity.value,
               "capability_id": http_baseline.CAPABILITY_ID}
              for cid, _header, title, severity, _impact, _fix
              in http_baseline.BASELINE_CHECKS]
    catalog = {"schema_version": SCHEMA_VERSION,
               "profiles": [_profile_payload(PROFILES[name]) for name in PROFILE_ORDER],
               "checks": sorted(checks, key=lambda item: item["check_id"])}
    return _sha(_canonical(catalog))


class _ProfileHandler(BaseHTTPRequestHandler):
    def version_string(self) -> str:
        return self.server.fixture_profile.server_banner or ""

    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(404)
            return
        profile = self.server.fixture_profile
        body = _canonical({"service": "lightup-lab-fixture", "profile": profile.profile_id})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in profile.headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class _ProfileServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, profile: FixtureProfile) -> None:
        super().__init__(("127.0.0.1", 0), _ProfileHandler)
        self.fixture_profile = profile


def _canonical_observation(profile: FixtureProfile, url: str) -> tuple[dict[str, Any], bytes]:
    observation = http_baseline.observe(url)
    # Date is time-dependent; all remaining headers are fixture-controlled.
    headers = sorted([[name.lower(), value] for name, value in observation.headers
                      if name.lower() != "date"], key=lambda pair: (pair[0], pair[1]))
    payload = {"schema_version": SCHEMA_VERSION, "profile_id": profile.profile_id,
               "fixture_sha256": _profile_sha(profile), "status": observation.status,
               "headers": headers,
               "observed_check_ids": sorted(issue.check_id for issue in observation.issues)}
    return payload, _canonical(payload)


def _store_evidence(store: StateStore, run_id: str, kind: str, payload: bytes,
                    metadata: dict[str, str]) -> tuple[str, str]:
    evidence_id = store.add_evidence(run_id, http_baseline.CAPABILITY_ID, kind,
                                     "lightup.lab_replay", payload, metadata)
    record = store.get_evidence(evidence_id)
    digest = _sha(payload)
    if record.sha256 != digest:
        raise RuntimeError("stored evidence digest did not match canonical payload")
    return evidence_id, record.sha256


def _record_event(ledger: sqlite3.Connection, event_type: str,
                  payload: dict[str, Any]) -> str:
    payload_json = _canonical(payload).decode("utf-8")
    event_id = _sha(_canonical({"event_type": event_type, "payload": payload}))
    ledger.execute("INSERT OR IGNORE INTO replay_events VALUES(?,?,?)",
                   (event_id, event_type, payload_json))
    row = ledger.execute("SELECT event_type,payload_json FROM replay_events WHERE event_id=?",
                         (event_id,)).fetchone()
    if row is None or row[0] != event_type or row[1] != payload_json:
        raise RuntimeError("replay event identity collision")
    ledger.commit()
    return event_id


def _record_evidence_payload(ledger: sqlite3.Connection, evidence_sha: str,
                             evidence_kind: str, profile_id: str, payload: bytes) -> None:
    payload_json = payload.decode("utf-8")
    if _sha(payload) != evidence_sha or _canonical(json.loads(payload_json)).decode("utf-8") != payload_json:
        raise RuntimeError("canonical evidence payload failed digest/canonical checks")
    ledger.execute("INSERT OR IGNORE INTO replay_evidence VALUES(?,?,?,?)",
                   (evidence_sha, evidence_kind, profile_id, payload_json))
    row = ledger.execute(
        "SELECT payload_json FROM replay_evidence WHERE evidence_sha256=? AND evidence_kind=? AND profile_id=?",
        (evidence_sha, evidence_kind, profile_id)).fetchone()
    if row is None or row[0] != payload_json:
        raise RuntimeError("stored evidence payload did not match its content digest")
    ledger.commit()


def _finding_key(profile: FixtureProfile, check_id: str) -> str:
    return _sha(_canonical({"profile_id": profile.profile_id,
                            "fixture_sha256": _profile_sha(profile), "check_id": check_id}))


def _build_replay(stage: Path) -> tuple[dict[str, Any], bytes, str]:
    state_path, domain_path, ledger_path = (stage / "state.sqlite3", stage / "domain.sqlite3",
                                            stage / "replay-ledger.sqlite3")
    state = StateStore(state_path)
    domain = DomainStore(domain_path)
    context = AccessContext(user_id="synthetic-fixture-operator", role=Role.OPERATOR)
    ledger = sqlite3.connect(ledger_path)
    ledger.executescript(_LEDGER_SCHEMA)
    server = _ProfileServer(PROFILES["exposed"])
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    profile_receipts: list[dict[str, Any]] = []
    exposed_result: dict[str, Any] | None = None
    exposed_evidence_sha = ""
    persisted_records = []
    title_to_check = {title: cid for cid, _header, title, _severity, _impact, _fix
                      in http_baseline.BASELINE_CHECKS}
    try:
        for profile_id in PROFILE_ORDER:
            profile = PROFILES[profile_id]
            server.fixture_profile = profile
            baseline = run_lab_baseline(url, state_path, expected=expected_findings(profile),
                                        engine_version=ENGINE_VERSION)
            observed, evidence_payload = _canonical_observation(profile, url)
            evidence_id, evidence_sha = _store_evidence(
                state, baseline["run_id"], "fixture-baseline-observation", evidence_payload,
                {"profile_id": profile_id, "fixture_sha256": _profile_sha(profile)})
            _record_evidence_payload(ledger, evidence_sha, "baseline", profile_id, evidence_payload)
            expected_ids = sorted(profile.expected_check_ids)
            engine_ids = sorted(item["check_id"] for item in baseline["findings"])
            observed_ids = observed["observed_check_ids"]
            matched = expected_ids == engine_ids == observed_ids
            event_payload = {"profile_id": profile_id, "fixture_sha256": _profile_sha(profile),
                             "expected_check_ids": expected_ids, "engine_check_ids": engine_ids,
                             "observed_check_ids": observed_ids, "evidence_sha256": evidence_sha,
                             "outcome": "MATCH" if matched else "MISMATCH"}
            event_id = _record_event(ledger, "baseline", event_payload)
            profile_receipts.append({**event_payload, "event_id": event_id})
            if profile_id == "exposed":
                exposed_result = dict(baseline)
                exposed_result["findings"] = [
                    {**finding, "evidence_ids": [evidence_id]} for finding in baseline["findings"]]
                engagement = ensure_lab_engagement(domain, context)
                persisted_records = persist_lab_findings(
                    domain, context, engagement.engagement_id, exposed_result)
                exposed_evidence_sha = evidence_sha
        if exposed_result is None:
            raise RuntimeError("exposed fixture baseline was not produced")
        server.fixture_profile = PROFILES["hardened"]
        stable_findings = sorted(
            ({"finding_key": _finding_key(PROFILES["exposed"], title_to_check[item.title]),
              "check_id": title_to_check[item.title]} for item in persisted_records),
            key=lambda item: item["check_id"])
        remediation_payload = {
            "kind": "synthetic_fixture_profile_transition", "from_profile": "exposed",
            "to_profile": "hardened", "state": "SIMULATED_APPLIED",
            "scope": "in-process 127.0.0.1 fixture only; no real system changed",
            "finding_keys": [item["finding_key"] for item in stable_findings],
            "check_ids": [item["check_id"] for item in stable_findings],
        }
        remediation_event_id = _record_event(ledger, "remediation", remediation_payload)
        retest_receipts: list[dict[str, Any]] = []
        for record in sorted(persisted_records, key=lambda item: title_to_check[item.title]):
            check_id = title_to_check[record.title]
            key = _finding_key(PROFILES["exposed"], check_id)
            updated = retest_finding(domain, context, record)
            retest_observation, retest_bytes = _canonical_observation(PROFILES["hardened"], url)
            _evidence_id, retest_sha = _store_evidence(
                state, exposed_result["run_id"], "fixture-retest-observation", retest_bytes,
                {"profile_id": "hardened", "finding_key": key})
            _record_evidence_payload(ledger, retest_sha, "retest", "hardened", retest_bytes)
            passed = updated.retest_status.value == "fixed" and not retest_observation["observed_check_ids"]
            retest_payload = {
                "finding_key": key, "check_id": check_id,
                "baseline_evidence_sha256": exposed_evidence_sha,
                "retest_evidence_sha256": retest_sha,
                "observed_check_ids": retest_observation["observed_check_ids"],
                "stored_retest_status": updated.retest_status.value,
                "outcome": "PASS" if passed else "FAIL",
            }
            event_id = _record_event(ledger, "retest", retest_payload)
            retest_receipts.append({**retest_payload, "event_id": event_id})
        profiles_match = all(item["outcome"] == "MATCH" for item in profile_receipts)
        retests_pass = bool(retest_receipts) and all(item["outcome"] == "PASS" for item in retest_receipts)
        receipt = {
            "schema_version": SCHEMA_VERSION, "engine_version": ENGINE_VERSION,
            "fixture_catalog_sha256": _catalog_sha(), "profiles": profile_receipts,
            "remediation": {**remediation_payload, "event_id": remediation_event_id},
            "retests": retest_receipts,
            "policy": {"network_scope": "loopback-only", "external_target_contacted": False,
                       "model_gateway_used": False, "live_remediation_performed": False,
                       "production_authority_granted": False},
            "outcome": "PASS" if profiles_match and retests_pass else "FAIL",
        }
        receipt_bytes = _canonical(receipt)
        receipt_sha = _sha(receipt_bytes)
        ledger.execute("INSERT OR IGNORE INTO replay_receipts VALUES(?,?)",
                       (receipt_sha, receipt_bytes.decode("utf-8")))
        stored = ledger.execute("SELECT receipt_json FROM replay_receipts WHERE receipt_sha256=?",
                                (receipt_sha,)).fetchone()
        if stored is None or stored[0] != receipt_bytes.decode("utf-8"):
            raise RuntimeError("stored replay receipt did not match canonical payload")
        ledger.commit()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        ledger.close()

    for database in (state_path, domain_path, ledger_path):
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for artifact in stage.iterdir():
        if artifact.is_file() and not artifact.is_symlink():
            os.chmod(artifact, 0o600)
    _verify_database_lineage(stage, receipt)
    return receipt, receipt_bytes, receipt_sha


def _require_private_artifact(path: Path, *, directory: bool) -> os.stat_result:
    """Reject replaced, shared, non-private or wrongly-owned bundle artifacts."""
    try:
        info = os.lstat(path)
    except OSError:
        raise PermissionError("private evidence artifact is unavailable") from None
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or mode & 0o077:
        raise PermissionError("evidence artifact is not owner-private")
    if directory:
        if not stat.S_ISDIR(info.st_mode) or mode & 0o700 != 0o700:
            raise PermissionError("evidence bundle directory permissions are unsafe")
    elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
          or mode & 0o600 != 0o600):
        raise PermissionError("evidence bundle file permissions are unsafe")
    return info


def _check_store_path_components(path: Path) -> None:
    """Fail closed on replaceable ancestors; /tmp-style sticky dirs are safe."""
    for candidate in (*reversed(path.parents), path):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise PermissionError("store path must not contain symlink components")
        if not stat.S_ISDIR(info.st_mode):
            raise PermissionError("store path components must be directories")
        if candidate == path:
            continue
        mode = stat.S_IMODE(info.st_mode)
        sticky_temp_dirs = {Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")}
        is_root_owned_sticky_temp = (
            candidate in sticky_temp_dirs and info.st_uid == 0 and bool(mode & stat.S_ISVTX)
        )
        if mode & 0o022 and not is_root_owned_sticky_temp:
            raise PermissionError("store path ancestor must not be group/other writable")


def _prepare_store_dir(raw_path: str) -> Path:
    path = Path(os.path.abspath(Path(raw_path).expanduser()))
    # Check both sides of mkdir: non-sticky writable ancestors can replace a
    # private child between operations. Only a root-owned sticky directory
    # (typically /tmp) is an acceptable shared-writable ancestor.
    _check_store_path_components(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _check_store_path_components(path)
    _require_private_artifact(path, directory=True)
    return path.resolve()


def _verify_database_lineage(bundle: Path, receipt: dict[str, Any]) -> None:
    raw_receipt = _canonical(receipt)
    digest = _sha(raw_receipt)
    receipt_json = raw_receipt.decode("utf-8")
    with sqlite3.connect(bundle / "replay-ledger.sqlite3") as ledger:
        stored_receipts = ledger.execute(
            "SELECT receipt_sha256,receipt_json FROM replay_receipts"
        ).fetchall()
        if stored_receipts != [(digest, receipt_json)]:
            raise RuntimeError("ledger receipt set mismatch")
        event_payloads: dict[str, tuple[str, dict[str, Any]]] = {}
        for event_id, event_type, raw in ledger.execute(
            "SELECT event_id,event_type,payload_json FROM replay_events"
        ):
            payload = json.loads(raw)
            if (not isinstance(payload, dict)
                    or _canonical(payload).decode("utf-8") != raw
                    or _sha(_canonical({"event_type": event_type, "payload": payload})) != event_id):
                raise RuntimeError("replay event integrity check failed")
            event_payloads[event_id] = (event_type, payload)
        evidence: set[tuple[str, str, str]] = set()
        for sha, kind, profile, raw in ledger.execute(
            "SELECT evidence_sha256,evidence_kind,profile_id,payload_json FROM replay_evidence"
        ):
            payload = json.loads(raw)
            if (not isinstance(payload, dict)
                    or _canonical(payload).decode("utf-8") != raw
                    or _sha(raw.encode("utf-8")) != sha):
                raise RuntimeError("evidence payload integrity check failed")
            evidence.add((sha, kind, profile))

    expected_events: dict[str, tuple[str, dict[str, Any]]] = {}
    for item in receipt["profiles"]:
        expected_events[item["event_id"]] = (
            "baseline", {key: value for key, value in item.items() if key != "event_id"}
        )
    remediation = receipt["remediation"]
    expected_events[remediation["event_id"]] = (
        "remediation", {key: value for key, value in remediation.items() if key != "event_id"}
    )
    for item in receipt["retests"]:
        expected_events[item["event_id"]] = (
            "retest", {key: value for key, value in item.items() if key != "event_id"}
        )
    expected_event_count = len(receipt["profiles"]) + 1 + len(receipt["retests"])
    if len(expected_events) != expected_event_count or set(event_payloads) != set(expected_events):
        raise RuntimeError("replay event set does not match receipt")
    for event_id, expected in expected_events.items():
        if event_payloads[event_id] != expected:
            raise RuntimeError("replay event payload does not match receipt")

    expected_evidence = {
        (item["evidence_sha256"], "baseline", item["profile_id"])
        for item in receipt["profiles"]
    }
    expected_evidence.update(
        (item["retest_evidence_sha256"], "retest", "hardened")
        for item in receipt["retests"]
    )
    if evidence != expected_evidence:
        raise RuntimeError("evidence payload set does not match receipt")
    for item in receipt["retests"]:
        if ((item["baseline_evidence_sha256"], "baseline", "exposed") not in evidence
                or (item["retest_evidence_sha256"], "retest", "hardened") not in evidence):
            raise RuntimeError("retest receipt references missing evidence")
    if set(receipt["remediation"]["finding_keys"]) != {
        item["finding_key"] for item in receipt["retests"]
    }:
        raise RuntimeError("remediation and retest finding sets disagree")

    expected_state_evidence = {
        (item["evidence_sha256"], "fixture-baseline-observation",
         item["profile_id"], item["fixture_sha256"], None)
        for item in receipt["profiles"]
    }
    expected_state_evidence.update(
        (item["retest_evidence_sha256"], "fixture-retest-observation",
         "hardened", None, item["finding_key"])
        for item in receipt["retests"]
    )
    state_ids: set[str] = set()
    state_records: list[tuple[str, str, str, str | None, str | None]] = []
    exposed_evidence_ids: list[str] = []
    exposed_sha = next(
        item["evidence_sha256"] for item in receipt["profiles"]
        if item["profile_id"] == "exposed"
    )
    with sqlite3.connect(bundle / "state.sqlite3") as state:
        rows = state.execute(
            "SELECT evidence_id,sha256,kind,metadata_json "
            "FROM evidence WHERE source='lightup.lab_replay'"
        ).fetchall()
        for evidence_id, sha, kind, raw_meta in rows:
            meta = json.loads(raw_meta)
            if not isinstance(meta, dict):
                raise RuntimeError("StateStore evidence metadata is invalid")
            if kind == "fixture-baseline-observation":
                if set(meta) != {"profile_id", "fixture_sha256"}:
                    raise RuntimeError("baseline StateStore metadata is invalid")
                record = (sha, kind, meta["profile_id"], meta["fixture_sha256"], None)
                if sha == exposed_sha and meta["profile_id"] == "exposed":
                    exposed_evidence_ids.append(evidence_id)
            elif kind == "fixture-retest-observation":
                if set(meta) != {"profile_id", "finding_key"}:
                    raise RuntimeError("retest StateStore metadata is invalid")
                record = (sha, kind, meta["profile_id"], None, meta["finding_key"])
            else:
                raise RuntimeError("StateStore contains unexpected fixture evidence")
            state_records.append(record)
            state_ids.add(evidence_id)
    if (len(state_records) != len(expected_state_evidence)
            or set(state_records) != expected_state_evidence):
        raise RuntimeError("StateStore evidence set does not match receipt")
    if len(exposed_evidence_ids) != 1:
        raise RuntimeError("exposed baseline evidence identity is ambiguous")

    expected_checks = {item["check_id"] for item in receipt["retests"]}
    title_to_check = {
        title: check_id
        for check_id, _header, title, _severity, _impact, _fix
        in http_baseline.BASELINE_CHECKS
    }
    with sqlite3.connect(bundle / "domain.sqlite3") as domain:
        findings = domain.execute(
            "SELECT title,evidence_ids_json,retest_status FROM findings"
        ).fetchall()
    if len(findings) != len(receipt["retests"]):
        raise RuntimeError("finding/retest counts disagree")
    actual_checks = []
    for title, raw_ids, status in findings:
        check_id = title_to_check.get(title)
        if check_id is None:
            raise RuntimeError("domain finding is not present in the fixture catalog")
        actual_checks.append(check_id)
        ids = json.loads(raw_ids)
        if status != "fixed" or ids != [exposed_evidence_ids[0]] or any(
            item not in state_ids for item in ids
        ):
            raise RuntimeError("durable finding evidence lineage is incomplete")
    if len(actual_checks) != len(expected_checks) or set(actual_checks) != expected_checks:
        raise RuntimeError("domain finding set does not match retest receipt")

def _verify_existing_bundle(path: Path, receipt_bytes: bytes, digest: str) -> None:
    # Idempotent reuse must not turn a formerly private receipt public after a
    # chmod, replacement, or hard-link operation between invocations.
    _require_private_artifact(path, directory=True)
    receipt_path = path / "receipt.json"
    _require_private_artifact(receipt_path, directory=False)
    if receipt_path.read_bytes() != receipt_bytes:
        raise RuntimeError("existing bundle does not match the canonical receipt")
    checksum = path / "receipt.sha256"
    _require_private_artifact(checksum, directory=False)
    if checksum.read_text(encoding="ascii") != f"{digest}  receipt.json\n":
        raise RuntimeError("existing bundle checksum does not match")
    for name in ("state.sqlite3", "domain.sqlite3", "replay-ledger.sqlite3"):
        _require_private_artifact(path / name, directory=False)
    _verify_database_lineage(path, json.loads(receipt_bytes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-fixture-replay",
        description="Replay built-in loopback fixtures and persist a deterministic evidence receipt.",
    )
    parser.add_argument(
        "--store-dir",
        default=str(Path.home() / ".local" / "state" / "lightup" / "lab-fixture-replays"),
        help="private directory for immutable content-addressed replay bundles",
    )
    args = parser.parse_args(argv)
    try:
        store_dir = _prepare_store_dir(args.store_dir)
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=store_dir) as staging:
            stage = Path(staging)
            receipt, receipt_bytes, digest = _build_replay(stage)
            (stage / "receipt.json").write_bytes(receipt_bytes)
            (stage / "receipt.sha256").write_text(f"{digest}  receipt.json\n", encoding="ascii")
            for artifact in stage.iterdir():
                if artifact.is_file() and not artifact.is_symlink():
                    os.chmod(artifact, 0o600)
            destination = store_dir / digest
            if destination.exists() or destination.is_symlink():
                _verify_existing_bundle(destination, receipt_bytes, digest)
            else:
                os.replace(stage, destination)
            print(json.dumps({
                "outcome": receipt["outcome"], "receipt_sha256": digest,
                "store_path": str(destination),
                "profiles_matched": sum(item["outcome"] == "MATCH" for item in receipt["profiles"]),
                "profiles_total": len(receipt["profiles"]),
                "retests_passed": sum(item["outcome"] == "PASS" for item in receipt["retests"]),
                "retests_total": len(receipt["retests"]),
            }, sort_keys=True))
            return 0 if receipt["outcome"] == "PASS" else 2
    except Exception as exc:
        # Do not expose private filesystem paths or endpoint details in CLI errors.
        print(json.dumps({"outcome": "FAIL", "error": type(exc).__name__,
                          "message": "fixture replay failed; private path and endpoint details omitted"},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
