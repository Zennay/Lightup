"""Offline native reopen of one PRIVATE HUMAN source-selected history workroom.

No source trust, consent, verified findings or authorized action is inferred.
Checks only bounded originally produced local files and presentation consistency.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .finding_export_review import _RETESTS, _SEVERITIES
from .finding_export_review_history import _HISTORY_HOLD, _html, _load_file
from .finding_export_review_publish import _SAFE_NAME, _private_parent

_NAMES = ("history.html", "history.json", "REVIEW_ONLY.txt")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_KINDS = ("added", "absent", "changed", "unchanged")
_FIELDS = ("finding_id", "title", "severity", "retest_status", "remediation")


def _pairs_unique(pairs: list[tuple[str, object]]) -> dict:
    found: dict = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("duplicate private history JSON key")
        found[key] = value
    return found


def _exact_int(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _admit_history(data: object) -> dict:
    """Strict bounded native history *format*, never client/source identity."""
    if type(data) is not dict or set(data) != {
        "schema", "classification", "packet_count",
        "operator_selected_csv_sha256", "human_declared_same_scope",
        "chronology_authenticated", "source_authenticated",
        "client_consent_verified", "remediation_verified",
        "release_approved", "transitions",
    }:
        raise ValueError("unknown native private history schema")
    if (data["schema"] != "lightup.private.finding-review-history.v1"
            or data["classification"] != "PRIVATE_HUMAN_REVIEW_ONLY"
            or data["human_declared_same_scope"] is not True
            or any(data[name] is not False for name in (
                "chronology_authenticated", "source_authenticated",
                "client_consent_verified", "remediation_verified",
                "release_approved",
            ))):
        raise ValueError("source/authority claims outside PRIVATE/HUMAN contract")
    count = data["packet_count"]
    sha = data["operator_selected_csv_sha256"]
    steps = data["transitions"]
    if (not _exact_int(count, 2, 12)
            or type(sha) is not list or len(sha) != count
            or any(type(x) is not str or _HEX.fullmatch(x) is None for x in sha)
            or len(set(sha)) != len(sha)
            or type(steps) is not list or len(steps) != count - 1):
        raise ValueError("invalid selected original packet history identity")
    for i, step in enumerate(steps, 1):
        if type(step) is not dict or set(step) != {
            "from_ordinal", "to_ordinal", "counts", "items",
        }:
            raise ValueError("invalid native selected transition")
        if (type(step["from_ordinal"]) is not int or step["from_ordinal"] != i
                or type(step["to_ordinal"]) is not int
                or step["to_ordinal"] != i + 1):
            raise ValueError("non-sequential HUMAN-selected ordinal")
        totals = step["counts"]
        rows = step["items"]
        if (type(totals) is not dict or set(totals) != set(_KINDS)
                or any(not _exact_int(totals[key], 0, 256) for key in _KINDS)
                or type(rows) is not list or len(rows) > 256
                or sum(totals.values()) != len(rows)):
            raise ValueError("invalid native private transition counts")
        seen_ids: set[str] = set()
        observed = dict.fromkeys(_KINDS, 0)
        for item in rows:
            if type(item) is not dict or set(item) != {
                "finding_id", "change_kind", "changed_display_fields",
                "earlier_reported_severity", "later_reported_severity",
                "earlier_reported_retest_stage", "later_reported_retest_stage",
            }:
                raise ValueError("invalid native private finding transition")
            identity = item["finding_id"]
            kind = item["change_kind"]
            fields = item["changed_display_fields"]
            if (type(identity) is not str or not identity or
                    len(identity.encode("utf-8", "strict")) > 1024
                    or identity in seen_ids
                    or type(kind) is not str or kind not in _KINDS
                    or type(fields) is not list
                    or len(fields) > len(_FIELDS)
                    or len(fields) != len(set(fields))
                    or any(type(f) is not str or f not in _FIELDS
                           for f in fields)):
                raise ValueError("invalid HUMAN change/identity")
            seen_ids.add(identity)
            observed[kind] += 1
            prior_sev = item["earlier_reported_severity"]
            later_sev = item["later_reported_severity"]
            prior_stage = item["earlier_reported_retest_stage"]
            later_stage = item["later_reported_retest_stage"]
            if (any(value is not None and
                    (type(value) is not str or value not in _SEVERITIES)
                    for value in (prior_sev, later_sev))
                    or any(value is not None and
                    (type(value) is not str or value not in _RETESTS)
                    for value in (prior_stage, later_stage))):
                raise ValueError("unknown reported source stage or severity")
            if kind == "added":
                valid = (prior_sev is None and prior_stage is None
                         and later_sev is not None and later_stage is not None
                         and not fields)
            elif kind == "absent":
                valid = (later_sev is None and later_stage is None
                         and prior_sev is not None and prior_stage is not None
                         and not fields)
            elif kind == "unchanged":
                valid = (all(value is not None for value in (
                    prior_sev, later_sev, prior_stage, later_stage))
                    and prior_sev == later_sev and prior_stage == later_stage
                    and not fields)
            else:
                valid = (all(value is not None for value in (
                    prior_sev, later_sev, prior_stage, later_stage))
                    and bool(fields))
            if not valid:
                raise ValueError("invalid reported native change semantics")
        if totals != observed:
            raise ValueError("private history counts do not match HUMAN records")
    return data


def inspect_private_review_history(workspace: str | Path) -> tuple[str, int]:
    """Admit an independently received private local history; don't approve it."""
    path = Path(workspace)
    if not path.is_absolute() or _SAFE_NAME.fullmatch(path.name) is None:
        raise ValueError("choose absolute owner-private native workroom")
    parent_fd = _private_parent(path.parent)
    folder_fd = -1
    try:
        folder_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(folder_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or set(os.listdir(folder_fd)) != set(_NAMES)):
            raise ValueError("unsafe native PRIVATE history inventory")
        html_b, json_b, hold_b = [
            _load_file(folder_fd, name, bound)
            for name, bound in zip(_NAMES, (3_000_000, 3_000_000, 2_000))
        ]
    finally:
        if folder_fd >= 0:
            os.close(folder_fd)
        os.close(parent_fd)
    try:
        html_text = html_b.decode("utf-8", "strict")
        json_text = json_b.decode("utf-8", "strict")
        hold_text = hold_b.decode("utf-8", "strict")
        payload = json.loads(json_text, object_pairs_hook=_pairs_unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(
                                 ValueError("non-finite private JSON")))
        payload = _admit_history(payload)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid bounded PRIVATE history representation") from exc
    if (hold_text != _HISTORY_HOLD + "\n"
            or html_text != _html(payload)
            or json_text != json.dumps(payload, ensure_ascii=False,
                                       sort_keys=True, indent=2) + "\n"):
        raise ValueError("PRIVATE history HTML/JSON/HOLD byte consistency failed")
    # SHA of this unsigned *local presentation*, not source attestation.
    return hashlib.sha256(json_b).hexdigest(), payload["packet_count"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE HUMAN native offline history reopening. NOT release approval.")
    parser.add_argument("--workspace", required=True, help="Existing owner-only 0700 history directory")
    args = parser.parse_args()
    try:
        sha, count = inspect_private_review_history(args.workspace)
    except (ValueError, OSError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3
    print("PRIVATE HUMAN REVIEW ONLY; packet count=" + str(count))
    print("Unsigned local history JSON SHA-256=" + sha)
    return 2


if __name__ == "__main__":
    sys.exit(main())
