"""Offline proof-manifest verifier. No network, filesystem writes or target execution.

Usage: PYTHONPATH=src python scripts/verify_scope_proof_manifest.py evidence.json
This script only checks an evidence *index*; it cannot prove the referenced
artifacts are authentic. Independent review of the immutable SHA is mandatory.
"""
import json
import re
import sys
from pathlib import Path

REQUIRED = ("schema_version", "implementation_sha", "base_sha", "trusted_grant_reviewed",
            "revocation_race_passed", "denied_side_effects_zero",
            "positive_loopback_control_passed", "hosted_py311_sha",
            "hosted_py314_sha", "permanent_vps_sha", "owner_review_sha",
            "real_target_activation_disabled")
SHA = re.compile(r"[0-9a-f]{40}\Z")


MAX_MANIFEST_BYTES = 64 * 1024


def verify(data):
    if type(data) is not dict:
        return ["manifest must be an object"]
    errors = [f"missing {key}" for key in REQUIRED if key not in data]
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        errors.append("schema_version: must be integer 1")
    # Unknown fields are rejected: a misspelled or forged authority field must
    # not quietly appear in an otherwise passing evidence index.
    allowed = set(REQUIRED) | {"denial_side_effect_counts"}
    errors.extend(f"unknown field {key}" for key in data if key not in allowed)
    if type(data.get("denial_side_effect_counts")) is dict:
        boundaries = {"handler", "socket", "queue", "action_evidence"}
        errors.extend(f"unknown denial boundary {key}" for key in data["denial_side_effect_counts"] if key not in boundaries)
    sha = data.get("implementation_sha")
    for key in ("implementation_sha", "base_sha", "hosted_py311_sha",
                "hosted_py314_sha", "permanent_vps_sha", "owner_review_sha"):
        value = data.get(key)
        if type(value) is not str or SHA.fullmatch(value) is None:
            errors.append(f"{key}: expected lowercase 40-character commit SHA")
        elif value == "0" * 40:
            errors.append(f"{key}: null placeholder SHA is forbidden")
    base_sha = data.get("base_sha")
    if (type(sha) is str and SHA.fullmatch(sha)
            and type(base_sha) is str and SHA.fullmatch(base_sha)
            and sha == base_sha):
        errors.append("implementation_sha: must differ from base_sha")
    if type(sha) is str and SHA.fullmatch(sha):
        for key in ("hosted_py311_sha", "hosted_py314_sha", "permanent_vps_sha", "owner_review_sha"):
            if data.get(key) != sha:
                errors.append(f"{key}: does not match implementation_sha")
    for key in ("trusted_grant_reviewed", "revocation_race_passed",
                "denied_side_effects_zero", "positive_loopback_control_passed",
                "real_target_activation_disabled"):
        if data.get(key) is not True:
            errors.append(f"{key}: must be literal true")
    side_effects = data.get("denial_side_effect_counts")
    if type(side_effects) is not dict:
        errors.append("denial_side_effect_counts: missing object")
    else:
        for boundary in ("handler", "socket", "queue", "action_evidence"):
            if type(side_effects.get(boundary)) is not int or side_effects[boundary] != 0:
                errors.append(f"denial_side_effect_counts.{boundary}: must be integer 0")
    return errors


def reject_duplicate_keys(pairs):
    """Prevent JSON parser last-key-wins from overwriting denial evidence."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main(argv):
    if len(argv) != 2:
        print("usage: verify_scope_proof_manifest.py path/to/evidence.json", file=sys.stderr)
        return 2
    try:
        with Path(argv[1]).open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError("proof manifest exceeds maximum byte length")
        data = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=reject_duplicate_keys,
                          parse_constant=lambda value: (_ for _ in ()).throw(
                              ValueError(f"invalid JSON constant: {value}")))
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"HOLD: invalid manifest: {exc}", file=sys.stderr)
        return 2
    errors = verify(data)
    if errors:
        print("HOLD: " + "; ".join(errors))
        return 1
    print("INDEX CHECK PASS ONLY: evidence references are internally consistent; "
          "not authorization or release approval")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
