"""Opt-in, stdin-only and non-authorizing JSON schema review (#1520).

Run as: PYTHONPATH=src python -m scripts.scope_parameter_schema_cli_1520
Exits 2 (REVIEW_ONLY) or 3 (HOLD), never 0. Does not echo input,
contact targets, issue consent or run ToolRegistry/ToolExecutor.
"""
from __future__ import annotations

import json
import sys

from lightup.ai.orchestration import ParamKind, ToolDefinition, ToolParameter
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.scope_parameter_schema_review_1520 import review_parameter_schema

_MAX_INPUT = 8192
_FIELDS = ("name", "kind", "required")
_ACCEPTED = {
    "HOLD": '{"status":"HOLD","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}',
    "REVIEW_ONLY": '{"status":"REVIEW_ONLY","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}',
}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_constant):
    raise ValueError("nonstandard numeric constant")


def _review_input(raw: bytes) -> str:
    if not raw or len(raw) > _MAX_INPUT or not raw.isascii():
        return "HOLD"
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        # Exact serialization prevents aliases, whitespace ambiguity, escaped
        # Unicode, BOMs and noncanonical JSON re-encodings.
        if type(parsed) is not dict or list(parsed) != ["parameters"]:
            return "HOLD"
        canonical = json.dumps(
            parsed, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode("ascii")
        if canonical != raw:
            return "HOLD"
        items = parsed["parameters"]
        if type(items) is not list or len(items) > 32:
            return "HOLD"
        parameters = []
        for item in items:
            if type(item) is not dict or list(item) != list(_FIELDS):
                return "HOLD"
            if (
                type(item["name"]) is not str
                or type(item["kind"]) is not str
                or type(item["required"]) is not bool
            ):
                return "HOLD"
            parameters.append(
                ToolParameter(
                    name=item["name"],
                    kind=ParamKind(item["kind"]),
                    required=item["required"],
                )
            )
        definition = ToolDefinition(
            tool_id="fictional_schema_1520",
            capability_id="external-attack-surface",
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="Unwired fictional review",
            parameters=tuple(parameters),
        )
        return review_parameter_schema(definition).status
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        return "HOLD"


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(_MAX_INPUT + 1)
        verdict = _review_input(raw)
    except (OSError, ValueError, TypeError, RecursionError):
        verdict = "HOLD"
    print(_ACCEPTED[verdict])
    return 2 if verdict == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
