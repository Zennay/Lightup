"""Opt-in stdin-only fictional scope history reviewer; NEVER grants rights.

This command does not import or invoke LightUp authorization, handler or
target modules. It returns exit 2 (inert REVIEW_ONLY) or 3 (generic HOLD),
never exit 0. Both carry four literal false authority fields.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import sys

from .fictional_scope_delta_review_1501 import (
    FictionalScopeProposal,
    ScopeHistoryReview,
    review_fictional_scope_history,
)

_CONTRACT = "FICTIONAL-SCOPE-HISTORY-1501-V1"
_MAX_BYTES = 32768
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)
_FIELDS = frozenset(
    ("assets", "capabilities", "exclusions", "risk", "valid_from", "valid_until")
)


def _reject(_: object) -> None:
    raise ValueError("noncanonical JSON number")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("duplicate JSON property")
        record[key] = value
    return record


def _utc(value: object) -> datetime:
    if type(value) is not str or len(value) != 20 or _INSTANT.fullmatch(value) is None:
        raise ValueError("invalid UTC instant")
    # Explicit ASCII field decoding avoids strptime's implicit locale and
    # format-cache initialization. All ranges and leap days are checked by
    # the built-in datetime constructor; no timezone conversion is attempted.
    stamp = datetime(
        int(value[0:4]), int(value[5:7]), int(value[8:10]),
        int(value[11:13]), int(value[14:16]), int(value[17:19]),
        tzinfo=timezone.utc,
    )
    if (
        f"{stamp.year:04d}-{stamp.month:02d}-{stamp.day:02d}"
        f"T{stamp.hour:02d}:{stamp.minute:02d}:{stamp.second:02d}Z"
    ) != value:
        raise ValueError("noncanonical instant")
    return stamp


def _load(raw: bytes) -> ScopeHistoryReview:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_BYTES:
        raise ValueError("invalid input size")
    # ASCII, no whitespace decorations, no alternate JSON key order/escapes,
    # duplicates, floats or NaN. Optional SINGLE LF is permitted.
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or raw.endswith(b"\n"):
        raise ValueError("invalid framing")
    value = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=_object,
        parse_float=_reject,
        parse_constant=_reject,
    )
    if raw.decode("ascii") != json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ):
        raise ValueError("noncanonical JSON")
    if type(value) is not dict or set(value) != {"contract", "history"}:
        raise ValueError("unexpected top-level fields")
    if value["contract"] != _CONTRACT or type(value["contract"]) is not str:
        raise ValueError("unknown contract")
    items = value["history"]
    if type(items) is not list or not 2 <= len(items) <= 16:
        raise ValueError("invalid history")
    result = []
    for item in items:
        if type(item) is not dict or set(item) != _FIELDS:
            raise ValueError("invalid entry")
        fields = {}
        for name in ("assets", "capabilities", "exclusions"):
            raw_list = item[name]
            if type(raw_list) is not list or len(raw_list) > 16:
                raise ValueError("invalid collection")
            # Never coerce object types into strings.
            fields[name] = tuple(raw_list)
        result.append(FictionalScopeProposal(
            assets=fields["assets"],
            capabilities=fields["capabilities"],
            exclusions=fields["exclusions"],
            risk=item["risk"],
            valid_from=_utc(item["valid_from"]),
            valid_until=_utc(item["valid_until"]),
        ))
    return review_fictional_scope_history(tuple(result))



def _validated_review(value: object) -> ScopeHistoryReview:
    """Rebuild an outcome from allowlisted inert fields before JSON emission.

    Even a frozen Python dataclass can be rewritten with object.__setattr__ in
    the same process. Never serialize a caller-poisoned status/dimension or
    tainted authority flag without independently checking the entire shape.
    """
    generic = ScopeHistoryReview("HOLD", 0, None, (), ())
    if type(value) is not ScopeHistoryReview:
        return generic
    try:
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            if getattr(value, flag) is not False:
                return generic
        return ScopeHistoryReview(
            value.status, value.transition_count, value.first_held_step,
            value.expanded_dimensions, value.narrowed_dimensions,
            value.held_steps, value.held_step_dimensions,
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        return generic


def main() -> int:
    review = ScopeHistoryReview("HOLD", 0, None, (), ())
    if sys.argv[1:] == ["--offline-review-only"]:
        try:
            review = _load(sys.stdin.buffer.read(_MAX_BYTES + 1))
        except (ValueError, UnicodeError, TypeError, OverflowError,
                RecursionError, OSError):
            # Stdin read/parse failure is a generic HOLD, not a traceback
            # that could expose source input or accidentally exit with 0.
            pass
    review = _validated_review(review)
    report = {
        "contract": _CONTRACT,
        "status": review.status,
        "transition_count": review.transition_count,
        "first_held_step": review.first_held_step,
        "held_steps": review.held_steps,
        "held_step_dimensions": review.held_step_dimensions,
        "expanded_dimensions": review.expanded_dimensions,
        "narrowed_dimensions": review.narrowed_dimensions,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }
    # A 16-entry maximal held-step witness serializes below 1,500 ASCII
    # bytes; guard future schema changes from accidentally producing an
    # unbounded or input-echoing report. A violation itself is generic HOLD.
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(payload) > 2048:
        review = ScopeHistoryReview("HOLD", 0, None, (), ())
        report.update(
            status="HOLD", transition_count=0, first_held_step=None,
            held_steps=(), held_step_dimensions=(),
            expanded_dimensions=(), narrowed_dimensions=(),
        )
        payload = json.dumps(report, sort_keys=True, separators=(",", ":"))
    try:
        sys.stdout.write(payload + "\n")
    except OSError:
        # A disconnected output pipe must never produce a success exit.
        return 3
    return 2 if review.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
