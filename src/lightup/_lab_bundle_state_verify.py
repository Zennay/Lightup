"""Read-only verification of the synthetic replay's persisted StateStore rows."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from . import lab_replay
from .workers import http_baseline


def _is_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite metadata number")


def _decode_metadata(raw: bytes) -> dict[str, Any]:
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("StateStore metadata is not an object")
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if canonical != raw:
        raise ValueError("StateStore metadata is not canonical")
    return value


def verify_state_rows(
    state_rows: list[tuple[Any, ...]],
    profiles: list[dict[str, Any]],
    retests: list[dict[str, Any]],
) -> tuple[dict[str, str], str]:
    if len(state_rows) != len(profiles) * 2 + len(retests):
        raise ValueError("StateStore evidence count mismatch")
    profile_by_id = {item["profile_id"]: item for item in profiles}
    retest_by_key = {item["finding_key"]: item for item in retests}
    if len(retest_by_key) != len(retests):
        raise ValueError("duplicate retest finding key")

    state_ids: set[str] = set()
    baseline_evidence_ids: dict[str, str] = {}
    baseline_runs: dict[str, str] = {}
    producer_runs: list[str] = []
    producer_assets_by_run: dict[str, str] = {}
    retest_rows: list[tuple[str, str]] = []
    for evidence_id, run_id, capability_id, kind, source, digest, raw_meta in state_rows:
        if (
            not isinstance(evidence_id, str)
            or not evidence_id
            or not isinstance(run_id, str)
            or not run_id
            or capability_id != http_baseline.CAPABILITY_ID
            or not _is_sha(digest)
        ):
            raise ValueError("StateStore evidence identity mismatch")
        meta = _decode_metadata(raw_meta.encode("utf-8"))
        if source == "lab-http-baseline":
            expected_keys = {
                "asset", "client_id", "engagement_id", "is_lab", "issues", "mode", "status"
            }
            if (
                kind != "http-baseline-observation"
                or set(meta) != expected_keys
                or not isinstance(meta.get("asset"), str)
                or not isinstance(meta.get("client_id"), str)
                or not meta["client_id"]
                or not isinstance(meta.get("engagement_id"), str)
                or not meta["engagement_id"]
                or not isinstance(meta.get("issues"), str)
                or meta.get("is_lab") != "true"
                or meta.get("mode") != "lab_autonomous"
                or meta.get("status") != "200"
            ):
                raise ValueError("built-in producer evidence is invalid")
            try:
                parsed = urlsplit(meta["asset"])
                port = parsed.port
            except ValueError:
                raise ValueError("built-in producer target is invalid") from None
            if (
                parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or port is None
                or not 1 <= port <= 65535
                or parsed.netloc != f"127.0.0.1:{port}"
                or parsed.path != "/"
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("built-in producer target is not literal loopback")
            producer_runs.append(run_id)
            producer_assets_by_run[run_id] = meta["asset"]
        elif source != "lightup.lab_replay":
            raise ValueError("unexpected StateStore evidence source")
        elif kind == "fixture-baseline-observation":
            profile_id = meta.get("profile_id")
            profile = profile_by_id.get(profile_id)
            if (
                profile is None
                or set(meta) != {"profile_id", "fixture_sha256"}
                or meta.get("fixture_sha256") != profile["fixture_sha256"]
                or digest != profile["evidence_sha256"]
                or profile_id in baseline_runs
            ):
                raise ValueError("baseline StateStore lineage mismatch")
            baseline_runs[profile_id] = run_id
            baseline_evidence_ids[profile_id] = evidence_id
        elif kind == "fixture-retest-observation":
            key = meta.get("finding_key")
            retest = retest_by_key.get(key)
            if (
                set(meta) != {"profile_id", "finding_key"}
                or meta.get("profile_id") != "hardened"
                or retest is None
                or digest != retest["retest_evidence_sha256"]
            ):
                raise ValueError("retest StateStore lineage mismatch")
            retest_rows.append((run_id, key))
        else:
            raise ValueError("unexpected StateStore evidence kind")
        state_ids.add(evidence_id)

    if (
        set(baseline_runs) != set(lab_replay.PROFILE_ORDER)
        or len(set(baseline_runs.values())) != len(profiles)
    ):
        raise ValueError("baseline run identities are not distinct")
    if (
        len(producer_runs) != len(profiles)
        or len(set(producer_runs)) != len(producer_runs)
        or set(producer_runs) != set(baseline_runs.values())
    ):
        raise ValueError("producer evidence is not bound to baseline runs")
    if (
        len(retest_rows) != len(retests)
        or any(run != baseline_runs["exposed"] for run, _key in retest_rows)
        or {key for _run, key in retest_rows} != set(retest_by_key)
    ):
        raise ValueError("retest run or finding binding mismatch")
    if len(state_ids) != len(state_rows):
        raise ValueError("duplicate StateStore evidence identity")
    return baseline_evidence_ids, producer_assets_by_run[baseline_runs["exposed"]]
