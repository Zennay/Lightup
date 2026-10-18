"""Private human-only request-binding coordination handoff.

Only fixed code-owned follow-up questions; not authenticated permission.
"""
from __future__ import annotations
from collections import Counter
from typing import Any

QUESTIONS = {
    "NOT_ADMINISTRATIVELY_APPROVED": (
        "operator", "Locate original client-origin request and arrange independent "
        "administrative review, never to be confused with consent."
    ),
    "REQUEST_MODE_NOT_AUTHORIZED_ASSESSMENT": (
        "client", "Confirm actual client assessment mode through an independently "
        "authenticated channel; do not upgrade passive work."
    ),
    "SOURCE_ROLE_OR_TENANT_PROVENANCE_MISMATCH": (
        "security_owner", "Reconcile persisted client, requester and reviewer "
        "role lineage with the domain owner before future authoritative action."
    ),
    "PROPOSED_RISK_NOT_COVERED": (
        "client", "Discuss the client's approved original risk ceiling; "
        "never widen it to match a proposed grant."
    ),
    "PROPOSED_LITERAL_SCOPE_NOT_COVERED": (
        "client", "Confirm every original literal asset independently; no DNS "
        "aliases, implicit wildcard or noncanonical CIDR expansion."
    ),
    "DECISION_CHRONOLOGY_INVALID": (
        "security_owner", "Review original persisted creation and decision times; "
        "an unsigned export cannot repair historical provenance."
    ),
    "SOURCE_OWNER_OTHER_INTEGRITY_CHECK_REQUIRED": (
        "security_owner", "Investigate the owner evaluator's original denial "
        "without overriding any canonical grant gate."
    ),
}


def _safe(value: Any, limit: int = 160) -> str:
    text = str(value)
    cleaned = "".join(c for c in text if 32 <= ord(c) <= 126)
    for char in ("\\", "*", "_", chr(96), "[", "]", "#"):
        cleaned = cleaned.replace(char, "\\" + char)
    return cleaned[:limit]


def _single(report: dict, label: str) -> list[str]:
    summary = report["summary"]
    lines = [
        "## " + _safe(label), "",
        "Disposition: **" + _safe(report["disposition"]) + "** (no permission).",
        "Proposed risk: " + str(report["source"]["requested_risk"]) +
        "; proposed original literal asset count: " +
        str(report["source"]["proposed_asset_count"]) + ".",
        "Original requests: " + str(summary["recorded_requests"]) +
        "; hypothetical administrative matches: " +
        str(summary["approved_candidate_matches"]) + ".",
        "Stored grant rows: " + str(summary["prior_stored_grant_rows"]) +
        "; historical unbound grant rows: " +
        str(summary["unbound_legacy_grant_rows"]) +
        " (neither implies execution authority).",
        "", "### Human follow-up by owner", "",
    ]
    work = Counter(
        (owner, code)
        for row in report["candidates"]
        for code in row["review_flags_non_authorizing"]
        for owner, _ in [QUESTIONS[code]]
    )
    if work:
        for (owner, code), count in sorted(work.items(), key=lambda pair: (
            {"security_owner": 0, "client": 1, "operator": 2}[pair[0][0]],
            pair[0][1],
        )):
            lines.append("- [" + _safe(owner) + "] " + _safe(code) +
                         " (" + str(count) + " historical request rows): " +
                         QUESTIONS[code][1])
    else:
        lines.append("- No listed mismatch; verify independent actual "
                     "consent and at-use revocation separately.")
    lines += ["", "### Request-level coordination (PRIVATE)", ""]
    for row in report["candidates"]:
        lines.append(
            "- Request #" + str(row["ordinal"]) +
            " (opaque token " + _safe(row["private_reference"]) +
            "; original ID " + _safe(row["request_id"] or "redacted") +
            "): " + _safe(row["stored_status"]) +
            " / " + _safe(row["request_source_status"]) +
            "; human reasons " +
            _safe(", ".join(row["review_flags_non_authorizing"]) or "none") + "."
        )
    lines += ["", "### Independent security owners", "",
              "- Verify real client origin and independent operator review.",
              "- The source-owner issuance transaction MUST reconfirm original "
              "scope, risk, roles, tenant and time.",
              "- Real separate authenticated client and operator consent, "
              "at-use revocation, source CI/privacy/security and HUMAN GO "
              "remain mandatory.", ""]
    return lines


def format_markdown(report: dict) -> str:
    if report["format"] == "lightup.request_binding_preparation.v1":
        sections = [_single(report, "Single original scope proposal")]
    elif report["format"] == "lightup.request_binding_scenarios_review.v1":
        sections = [
            _single(item["original_source"],
                    "Human alternative " + str(i) + ": " + item["label"])
            for i, item in enumerate(report["scenarios"], 1)
        ]
        changes = ["## Adjacent human alternatives (NOT chronology)", ""]
        for rec in report["adjacent_alternative_changes"]:
            changes.append(
                "- " + _safe(rec["from_scenario"]) + " to " +
                _safe(rec["to_scenario"]) + ": " +
                str(rec["still_potential"]) + " shared matches; " +
                str(rec["no_longer_matched_not_revoked"]) +
                " no longer matched (NOT revoked); " +
                str(rec["newly_matched_not_authorized"]) +
                " newly matched (NOT authorized)."
            )
        sections.append(changes + [""])
    else:
        raise ValueError("unsupported original private report format")
    lines = [
        "# LightUp private operator request-binding coordination", "",
        "**REVIEW_ONLY · CLIENT CONSENT FALSE · OPERATOR CONSENT FALSE · "
        "GRANT FALSE · EXECUTION FALSE · RELEASE FALSE**", "",
        "A real operator authenticated to the original data source, but this "
        "copy is unsigned and potentially stale, not an issued grant or consent.", "",
    ]
    for section in sections:
        lines.extend(section)
    lines.extend([
        "Keep this private source-linked brief only in independently "
        "authorized human communication channels.", "",
    ])
    return "\n".join(lines)
