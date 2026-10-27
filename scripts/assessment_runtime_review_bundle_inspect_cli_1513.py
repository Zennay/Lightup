"""Offline, stdlib-only structural intake of LightUp HUMAN lab-review JSON.

Accepts a locally supplied review-bundle-json artifact, never an asset/target,
and never authenticates original evidence, consent or permission to dispatch.
All invalid input produces a generic HOLD with no source identifiers.
"""
from __future__ import annotations

import json
import math
import os
import stat
import sys
from base64 import b64encode
from hashlib import sha256
from hmac import compare_digest
from html import escape
from decimal import Decimal, InvalidOperation

import assessment_runtime_report_html_1513 as reports


# The admitted schema has at most 64 anonymous cases and fixed metric fields.
# Reject oversized transferred bundles before allocating a JSON object graph.
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_FALSE_AUTHORITY = (
    "authorized", "consent_verified", "dispatch_allowed",
    "release_allowed", "source_provenance_authenticated",
)
_TOP_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "notice", "accepted_case_count", "metric_review", "human_actions",
    "resource_observations", *_FALSE_AUTHORITY,
))
_METRIC_FIELDS = frozenset((
    "metric", "baseline", "candidate", "delta",
    "source_regression_flag", "source_unknown_coverage",
))
_METRIC_CASE_FIELDS = frozenset((
    "scenario_ordinal", "source_status", "source_adverse_metric_count", "metrics",
))
_METRIC_SUMMARY_FIELDS = frozenset((
    "metric", "observed_case_count", "source_regression_case_count",
    "candidate_higher_case_count", "candidate_lower_case_count",
    "candidate_equal_case_count", "candidate_unknown_coverage_case_count",
))
_HUMAN_QUESTION_FIELDS = frozenset((
    "review_order", "scenario_ordinal", "human_review_group",
    "scope_policy_signal", "source_adverse_metric_count",
    "source_unknown_coverage", "matching_focus_signals",
    "suggested_human_question",
))
_RESOURCE_CASE_FIELDS = frozenset(("scenario_ordinal", "metrics"))
_RESOURCE_OBSERVATION_FIELDS = frozenset((
    "baseline", "candidate", "delta", "percent_change", "direction",
))
_RESOURCE_TOTAL_FIELDS = frozenset((
    "baseline_total", "candidate_total", "delta_total",
    "increased_cases", "decreased_cases",
))
_METRIC_REPORT_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "notice", "accepted_case_count", "source_adverse_case_count",
    "source_unknown_coverage_case_count", "metric_summary", "cases",
    *_FALSE_AUTHORITY,
))
_HUMAN_REPORT_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "focus_filter", "accepted_case_count", "selected_case_count",
    "excluded_case_count", "notice", "human_review_questions",
    *_FALSE_AUTHORITY,
))
_RESOURCE_REPORT_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "readout", "accepted_case_count", "cases", "aggregate",
    *_FALSE_AUTHORITY,
))
_REPORT_TYPES = frozenset(("single_case", "cohort", "scored_cohort"))
_STATUSES = frozenset(("REVIEW_ONLY", "HOLD"))
# Reproduce the original comparator's admitted-value and regression rules.
# This is a consistency check of unauthenticated values, not provenance proof.
_COUNTER_METRICS = frozenset((
    "valid_findings", "invalid_findings", "missed_findings",
    "coverage_assessed", "coverage_unknown", "scope_violations",
    "policy_violations", "human_interventions", "tool_calls",
))
_SCORE_METRICS = frozenset((
    "evidence_quality", "reproducibility", "remediation_quality",
    "retest_correctness",
))
_COST_METRICS = frozenset(("runtime_seconds", "compute_cost_usd"))
_HIGHER_IS_BETTER = frozenset(("valid_findings", "coverage_assessed", *_SCORE_METRICS))
_LOWER_IS_BETTER = frozenset((
    "invalid_findings", "missed_findings", "scope_violations", "policy_violations",
))


def _pairs_without_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _reject_constant(_value):
    raise ValueError("nonfinite JSON number")


def _shape(value, fields) -> bool:
    return type(value) is dict and set(value) == fields


def _false_authority(value) -> bool:
    return all(value.get(key) is False for key in _FALSE_AUTHORITY)


def _count(value) -> bool:
    return type(value) is int and value >= 0


def _finite_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


# Exported lab metrics are finite Python floats (minimum subnormal to
# maximum ~1e308); 64-case exact Decimal sums remain under 800 digits, and
# the largest legitimate percentage magnitude is below 1e700. Bound every
# transferred decimal *before* constructing arithmetic intermediates.
_MAX_DECIMAL_TEXT_CHARS = 1024
_MAX_DECIMAL_ADJUSTED_EXPONENT = 700


def _finite_decimal_text(value) -> bool:
    if type(value) is not str or not 1 <= len(value) <= _MAX_DECIMAL_TEXT_CHARS:
        return False
    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError):
        return False
    return (
        number.is_finite()
        and abs(number.adjusted()) <= _MAX_DECIMAL_ADJUSTED_EXPONENT
    )


def _canonical_metric_values(metric) -> bool:
    """Reject contradictory source-claimed deltas, flags and value classes."""
    name = metric["metric"]
    baseline, candidate, delta = (
        metric["baseline"], metric["candidate"], metric["delta"],
    )
    if name in _COUNTER_METRICS:
        if not all(type(value) is int and 0 <= value <= 1_000_000_000
                   for value in (baseline, candidate)):
            return False
    elif name in _SCORE_METRICS:
        if not all(_finite_number(value) and 0 <= value <= 1
                   for value in (baseline, candidate)):
            return False
    elif name in _COST_METRICS:
        if not all(
            _finite_number(value) and value >= 0
            and (type(value) is not int or value <= 1_000_000_000_000)
            for value in (baseline, candidate)
        ):
            return False
    else:
        return False
    if not _finite_number(delta) or candidate - baseline != delta:
        return False
    return metric["source_regression_flag"] is (
        (name in _HIGHER_IS_BETTER and candidate < baseline)
        or (name in _LOWER_IS_BETTER and candidate > baseline)
    )


def _admitted_components(payload) -> bool:
    metrics = payload["metric_review"]
    human = payload["human_actions"]
    resources = payload["resource_observations"]
    if not (
        _shape(metrics, _METRIC_REPORT_FIELDS)
        and _shape(human, _HUMAN_REPORT_FIELDS)
        and _shape(resources, _RESOURCE_REPORT_FIELDS)
    ):
        return False
    kind, status, count = (
        payload["report_type"], payload["source_status"],
        payload["accepted_case_count"],
    )
    # An admitted source bundle can only contain one standalone comparison
    # or 1–64 members of a bounded cohort. Reject semantically impossible
    # case counts even when the forged nested sections agree with each other.
    if not 1 <= count <= 64 or (kind == "single_case" and count != 1):
        return False
    for section in (metrics, human, resources):
        if (
            type(section["schema_version"]) is not int
            or section["schema_version"] != 1
            or section["report_type"] != kind
            or section["source_status"] != status
            or section["input_admitted"] is not True
            or section["accepted_case_count"] != count
            or not _false_authority(section)
        ):
            return False
    if (
        metrics["notice"] != "requires_human_review"
        or human["notice"] != "human_review_only"
        or human["focus_filter"] != "all"
        or not _count(human["selected_case_count"])
        or not _count(human["excluded_case_count"])
        or human["selected_case_count"] != count
        or human["excluded_case_count"] != 0
        or resources["readout"] != "informational_only"
        or not all(_count(v) for v in (
            metrics["source_adverse_case_count"],
            metrics["source_unknown_coverage_case_count"],
        ))
    ):
        return False

    metric_cases = metrics["cases"]
    human_questions = human["human_review_questions"]
    resource_cases = resources["cases"]
    if not (
        type(metric_cases) is list and type(human_questions) is list
        and type(resource_cases) is list and type(metrics["metric_summary"]) is list
        and len(metric_cases) == len(human_questions) == len(resource_cases) == count
        and len(metrics["metric_summary"]) == len(reports._METRIC_LABELS)
        and all(
            _shape(item, _METRIC_SUMMARY_FIELDS)
            and item["metric"] in reports._METRIC_LABELS
            and all(_count(item[key]) for key in (
                "observed_case_count", "source_regression_case_count",
                "candidate_higher_case_count", "candidate_lower_case_count",
                "candidate_equal_case_count",
                "candidate_unknown_coverage_case_count",
            ))
            for item in metrics["metric_summary"]
        )
    ):
        return False
    for case in metric_cases:
        if not (
            _shape(case, _METRIC_CASE_FIELDS)
            and _count(case["scenario_ordinal"])
            and case["source_status"] in _STATUSES
            and _count(case["source_adverse_metric_count"])
            and not (
                case["source_status"] == "REVIEW_ONLY"
                and case["source_adverse_metric_count"] > 0
            )
            and type(case["metrics"]) is list
            and len(case["metrics"]) == len(reports._METRIC_LABELS)
        ):
            return False
        for metric in case["metrics"]:
            if not (
                _shape(metric, _METRIC_FIELDS)
                and metric["metric"] in reports._METRIC_LABELS
                and all(_finite_number(metric[key]) for key in (
                    "baseline", "candidate", "delta",
                ))
                and metric["source_regression_flag"] in (True, False)
                and type(metric["source_regression_flag"]) is bool
                and type(metric["source_unknown_coverage"]) is bool
                and metric["source_unknown_coverage"] is (
                    metric["metric"] == "coverage_unknown" and metric["candidate"] > 0
                )
                and _canonical_metric_values(metric)
            ):
                return False
        if case["source_status"] != (
            "HOLD" if case["source_adverse_metric_count"] else "REVIEW_ONLY"
        ):
            return False
    for question in human_questions:
        if not (
            _shape(question, _HUMAN_QUESTION_FIELDS)
            and _count(question["review_order"])
            and _count(question["scenario_ordinal"])
            and _count(question["source_adverse_metric_count"])
            and _finite_number(question["source_unknown_coverage"])
            and type(question["scope_policy_signal"]) is bool
            and type(question["matching_focus_signals"]) is list
            and all(type(x) is str for x in question["matching_focus_signals"])
            and type(question["suggested_human_question"]) is str
        ):
            return False
    for case in resource_cases:
        if not (
            _shape(case, _RESOURCE_CASE_FIELDS)
            and _count(case["scenario_ordinal"])
            and _shape(case["metrics"], set(reports._EFFICIENCY_FIELDS))
        ):
            return False
        for metric in case["metrics"].values():
            if not (
                _shape(metric, _RESOURCE_OBSERVATION_FIELDS)
                and all(_finite_decimal_text(metric[key]) for key in (
                    "baseline", "candidate", "delta",
                ))
                and (metric["percent_change"] is None or
                     _finite_decimal_text(metric["percent_change"]))
                and Decimal(metric["baseline"]) >= 0
                and Decimal(metric["candidate"]) >= 0
                and metric["direction"] in ("increase", "decrease", "unchanged")
            ):
                return False
    if not _shape(resources["aggregate"], set(reports._EFFICIENCY_FIELDS)):
        return False
    for metric in resources["aggregate"].values():
        if not (
            _shape(metric, _RESOURCE_TOTAL_FIELDS)
            and all(_finite_decimal_text(metric[key]) for key in (
                "baseline_total", "candidate_total", "delta_total",
            ))
            and Decimal(metric["baseline_total"]) >= 0
            and Decimal(metric["candidate_total"]) >= 0
            and _count(metric["increased_cases"])
            and _count(metric["decreased_cases"])
        ):
            return False
    # A source-admitted HOLD is caused by at least one adverse comparator
    # metric. A clean population must be REVIEW_ONLY. These labels remain
    # advisory and never become an authorization or release verdict.
    adverse = any(case["source_adverse_metric_count"] > 0 for case in metric_cases)
    if status != ("HOLD" if adverse else "REVIEW_ONLY"):
        return False
    return (
        reports._bundle_case_alignment(metric_cases, human_questions, resource_cases)
        and reports._bundle_summary_alignment(metrics, resources)
    )


def _inspect(raw: bytes):
    payload = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs_without_duplicates,
        parse_constant=_reject_constant,
    )
    if not (
        _shape(payload, _TOP_FIELDS)
        and type(payload["schema_version"]) is int
        and payload["schema_version"] == 1
        and payload["report_type"] in _REPORT_TYPES
        and payload["source_status"] in _STATUSES
        and type(payload["input_admitted"]) is bool
        and _count(payload["accepted_case_count"])
        and _false_authority(payload)
    ):
        return None
    if payload["input_admitted"]:
        if (
            payload["notice"] != "requires_human_review"
            or payload["accepted_case_count"] <= 0
            or not _admitted_components(payload)
        ):
            return None
    elif not (
        payload["source_status"] == "HOLD"
        and payload["notice"] == "input_hold"
        and payload["accepted_case_count"] == 0
        and all(payload[name] is None for name in (
            "metric_review", "human_actions", "resource_observations",
        ))
    ):
        return None
    return payload


def _validated_review_bundle_packet(raw: bytes):
    """Admit at most one bounded complete packet; never expose partial input."""
    try:
        if type(raw) is bytes and len(raw) <= _MAX_INPUT_BYTES:
            return _inspect(raw)
    except (UnicodeError, ValueError, TypeError, KeyError, IndexError,
            OverflowError, AttributeError, ZeroDivisionError, InvalidOperation,
            RecursionError):
        pass
    return None


def _inspection_outcome(payload) -> dict:
    """Only public, source-minimal receipt fields; never original packet data."""
    return {
        "schema_version": 1,
        "format_consistent": payload is not None,
        "source_status": payload["source_status"] if payload is not None else "HOLD",
        "input_admitted": payload["input_admitted"] if payload is not None else False,
        "accepted_case_count": payload["accepted_case_count"] if payload is not None else 0,
        "notice": "structure_only_unauthenticated" if payload is not None else "input_hold",
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_provenance_authenticated": False,
    }


def inspect_review_bundle_bytes(raw: bytes) -> dict:
    """Source-minimal structural consistency readout, never provenance proof."""
    return _inspection_outcome(_validated_review_bundle_packet(raw))


def _read_private_bundle(path: str) -> bytes:
    """Pin an ordinary local file through symlink-free directory descriptors.

    A path can change between stat and open; first pin the regular inode with
    O_PATH, then open only that descriptor through procfs. Compare identity
    before and after the bounded read. Unsafe/unsupported platforms fail closed.
    """
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("invalid local review path")
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK", "O_PATH")
    if not all(hasattr(os, option) for option in required):
        raise ValueError("safe local review access unavailable")
    parts = (path if os.path.isabs(path) else os.path.join(os.getcwd(), path))
    components = [part for part in parts.split(os.sep) if part]
    if not components or any(part in (".", "..") for part in components):
        raise ValueError("unsafe local review path")

    directory_fd = os.open(
        os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    path_fd = None
    read_fd = None
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY |
                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        name = components[-1]
        original = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(original.st_mode):
            raise ValueError("local review is not a regular file")
        path_fd = os.open(
            name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        pinned = os.fstat(path_fd)

        def identity(info):
            return (
                info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns,
            )

        if (
            not stat.S_ISREG(pinned.st_mode)
            or identity(pinned) != identity(original)
            or pinned.st_size <= 0 or pinned.st_size > _MAX_INPUT_BYTES
        ):
            raise ValueError("local review changed or exceeds cap")
        read_fd = os.open(
            f"/proc/self/fd/{path_fd}",
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        before = os.fstat(read_fd)
        if identity(before) != identity(pinned):
            raise ValueError("local review changed during open")

        pieces = []
        remaining = _MAX_INPUT_BYTES + 1
        while remaining:
            piece = os.read(read_fd, min(65_536, remaining))
            if not piece:
                break
            pieces.append(piece)
            remaining -= len(piece)
        data = b"".join(pieces)
        after = os.fstat(read_fd)
        pinned_after = os.fstat(path_fd)
        final_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not data or len(data) > _MAX_INPUT_BYTES
            or not stat.S_ISREG(final_entry.st_mode)
            or identity(before) != identity(after)
            or identity(after) != identity(pinned_after)
            or identity(pinned_after) != identity(final_entry)
        ):
            raise ValueError("local review changed during read")
        return data
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if path_fd is not None:
            os.close(path_fd)
        os.close(directory_fd)


_RECEIPT_CSS = """
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,-apple-system,
BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1020;color:#e9efff}
*{box-sizing:border-box}body{margin:0;line-height:1.6}
main{width:min(960px,calc(100% - 32px));margin:clamp(24px,6vw,72px) auto}
header{padding-bottom:24px;border-bottom:1px solid #34435f}
.eyebrow{text-transform:uppercase;letter-spacing:.15em;font-size:.77rem;
font-weight:800;color:#a6b8dc}h1{font-size:clamp(1.9rem,5vw,3.25rem);
letter-spacing:-.04em;line-height:1.15;margin:.5rem 0 1rem}
h2{font-size:1.2rem;margin:0 0 .65rem}
p{max-width:72ch}strong{font-weight:750}
.muted{color:#b7c6e1}.pill{display:inline-flex;align-items:center;
padding:.35rem .9rem;border:1px solid #5471a1;border-radius:999px;
font-size:.83rem;letter-spacing:.025em;font-weight:800;background:#1a2a48}
.pill.hold{border-color:#bf8428;color:#ffe3a2;background:#392a15}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;
margin:24px 0}.metric,.panel{background:#141f35;border:1px solid #34435f;
border-radius:14px;padding:22px}.metric span{display:block;color:#bbcbe5;
font-size:.82rem}.metric strong{display:block;font-size:1.35rem;
overflow-wrap:anywhere;margin-top:6px}
.panel{margin:14px 0}.notice{border-color:#ad7c32;background:#2d2319}
.notice h2{color:#ffe3a2}ul{margin:.3rem 0 0;padding-left:1.3rem}
li+li{margin-top:.65rem}footer{font-size:.85rem;color:#b7c6e1;
margin-top:26px;border-top:1px solid #34435f;padding-top:14px}
@media(max-width:650px){.grid{grid-template-columns:1fr}
.metric,.panel{padding:17px}}
@media print{:root{color-scheme:light;background:#fff;color:#121c30}
.metric,.panel{background:#fff;border-color:#8591a3}.muted,footer,
.metric span,.eyebrow{color:#273449}.notice h2{color:#65410c}
.pill{background:#fff;color:#121c30}.pill.hold{background:#fff;color:#65410c}}
"""


def render_inspection_text(outcome: dict) -> str:
    """Fixed, anonymous operator receipt; a structure check is not approval."""
    consistency = "consistent" if outcome["format_consistent"] else "rejected"
    return (
        "LightUp | OFFLINE, UNAUTHENTICATED HUMAN RECEIPT\n"
        f"Packet structure: {consistency}\n"
        f"Source-reported state: {outcome['source_status']}\n"
        f"Input admitted: {'yes' if outcome['input_admitted'] else 'no'}\n"
        f"Anonymous cases: {outcome['accepted_case_count']}\n"
        "Authority, consent, provenance, dispatch, release: NEVER VERIFIED\n"
        "HUMAN REVIEW REQUIRED. No scan, approval or deployment permitted.\n"
    )


def render_inspection_html(outcome: dict) -> str:
    """Static offline receipt from fixed structural fields, never source data."""
    consistency = (
        "Structurally consistent" if outcome["format_consistent"]
        else "Input rejected or unreadable"
    )
    admitted = "Yes" if outcome["input_admitted"] else "No"
    source = escape(str(outcome["source_status"]), quote=True)
    count = escape(str(outcome["accepted_case_count"]), quote=True)
    state_class = "hold" if outcome["source_status"] == "HOLD" or not outcome["format_consistent"] else ""
    style_pin = b64encode(sha256(_RECEIPT_CSS.encode("utf-8")).digest()).decode("ascii")
    policy = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; "
        "object-src 'none'; frame-src 'none'; script-src 'none'; "
        "style-src 'sha256-" + style_pin + "'"
    )
    return (
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="'
        + escape(policy, quote=True) + '">'
        "<title>LightUp | Offline HUMAN receipt</title>"
        "<style>" + _RECEIPT_CSS + "</style></head><body><main>"
        "<header><p class='eyebrow'>LightUp / Assessment runtime / Private lab</p>"
        "<h1>Offline review receipt</h1>"
        "<p class='muted'>One locally received review bundle. This is a "
        "format-consistency observation, not verification of the evidence "
        "inside it.</p><span class='pill " + state_class + "'>"
        + escape(consistency, quote=True) + " / HUMAN only</span></header>"
        "<section class='grid' aria-label='Packet observation'>"
        "<div class='metric'><span>Source-reported status</span><strong>"
        + source + "</strong></div>"
        "<div class='metric'><span>Input admitted</span><strong>"
        + admitted + "</strong></div>"
        "<div class='metric'><span>Anonymous cases</span><strong>"
        + count + "</strong></div></section>"
        "<section class='panel notice' aria-labelledby='limits'><h2 id='limits'>"
        "Never an authorization</h2><p>Structural consistency does not "
        "authenticate who created this file, the validity of its underlying "
        "measurements, asset ownership, client or operator consent, revocation "
        "at use, security review, or approval to run or release anything.</p>"
        "<p><strong>All five authorization and provenance flags remain false."
        "</strong> This receipt cannot grant, dispatch, scan or deploy.</p>"
        "</section><section class='panel' aria-labelledby='next'>"
        "<h2 id='next'>Human review, outside this file</h2><ul>"
        "<li>Confirm original signed/source-bound evidence separately.</li>"
        "<li>Review any source-reported HOLD and all unknown coverage.</li>"
        "<li>Obtain the independent source-owner and privacy/security gates, "
        "fresh client/operator consent, revocation check and explicit HUMAN GO "
        "before any separate active action.</li></ul></section>"
        "<footer>No original case IDs, targets, URLs, paths or source notes. "
        "No scripts, external assets, network or forms. Print locally if "
        "needed; never present this receipt as a completion certificate."
        "</footer></main></body></html>\n"
    )


def _canonical_sha256(value) -> bool:
    """Strict 64-hex external digest, never a source-authentication claim."""
    return (
        type(value) is str
        and len(value) == 64
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    output_format = "json"
    expected_sha256 = None
    option_index = 0
    options_valid = True
    seen = set()
    # No argparse error echo: unexpected args and invalid digests fail closed
    # without printing any input path, expected digest or source content.
    while option_index + 1 < len(args) and args[option_index] in (
        "--format", "--expected-sha256",
    ):
        option = args[option_index]
        value = args[option_index + 1]
        if option in seen:
            options_valid = False
            break
        seen.add(option)
        if option == "--format":
            if value not in ("json", "text", "html", "bundle-html", "bundle-csv"):
                options_valid = False
                break
            output_format = value
        elif not _canonical_sha256(value):
            options_valid = False
            break
        else:
            expected_sha256 = value.lower()
        option_index += 2
    path = (
        args[option_index] if options_valid and len(args) == option_index + 1
        else None
    )
    outcome = _inspection_outcome(None)
    review_packet = None
    if path is not None:
        try:
            raw = _read_private_bundle(path)
            if expected_sha256 is not None and not compare_digest(
                sha256(raw).hexdigest(), expected_sha256,
            ):
                raise ValueError("offline bundle digest mismatch")
            # One bounded decode plus complete schema/numeric/source/rank check.
            # Reuse only the admitted in-memory packet for opt-in full outputs.
            # No rejected input, original path or partial case can be rendered.
            packet = _validated_review_bundle_packet(raw)
            outcome = _inspection_outcome(packet)
            if output_format in ("bundle-html", "bundle-csv"):
                review_packet = packet
        except (OSError, ValueError):
            pass
    if output_format == "bundle-html":
        print(reports._render_review_bundle_packet_html(
            review_packet if review_packet is not None else {
                "input_admitted": False, "source_status": "HOLD",
            }
        ), end="")
    elif output_format == "bundle-csv":
        print(reports._render_review_bundle_packet_csv(
            review_packet if review_packet is not None else {
                "input_admitted": False, "source_status": "HOLD",
            }
        ), end="")
    elif output_format == "html":
        print(render_inspection_html(outcome), end="")
    elif output_format == "text":
        print(render_inspection_text(outcome), end="")
    else:
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 2 if outcome["format_consistent"] and outcome["source_status"] == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
