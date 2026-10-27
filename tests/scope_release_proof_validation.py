"""Offline validation of scope-authorization proof records.

Validates *evidence metadata*, never grants deployment or execution permission.
No network/API calls. Refuses missing, stale or noncanonical run evidence.
"""
from __future__ import annotations

import re
from typing import Any


SHA40 = re.compile(r"^[0-9a-f]{40}$")
RUN_URL = re.compile(r"^https://github\.com/Zennay/Lightup/actions/runs/[1-9][0-9]*$")


def validate_proof_record(record: Any, *, expected_source_sha: str, expected_test_sha: str) -> bool:
    if type(record) is not dict:
        return False
    if type(expected_source_sha) is not str or not SHA40.fullmatch(expected_source_sha):
        return False
    if type(expected_test_sha) is not str or not SHA40.fullmatch(expected_test_sha):
        return False
    if set(record) != {
        "source_sha", "test_sha", "canonical_run_url", "conclusion",
        "runner_kind", "python_version", "observed_at", "gate_ids",
    }:
        return False
    if type(record["source_sha"]) is not str or record["source_sha"] != expected_source_sha:
        return False
    if type(record["test_sha"]) is not str or record["test_sha"] != expected_test_sha:
        return False
    if type(record["canonical_run_url"]) is not str or not RUN_URL.fullmatch(record["canonical_run_url"]):
        return False
    if record["conclusion"] != "success" or type(record["conclusion"]) is not str:
        return False
    if record["runner_kind"] != "self-hosted" or type(record["runner_kind"]) is not str:
        return False
    if type(record["python_version"]) is not str or record["python_version"] not in {"3.11", "3.14"}:
        return False
    if type(record["observed_at"]) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", record["observed_at"]
    ):
        return False
    ids = record["gate_ids"]
    if type(ids) is not list or not ids or any(type(value) is not str or not value for value in ids):
        return False
    if len(ids) != len(set(ids)):
        return False
    return True
