"""Read-only original-source HUMAN brief; no security authority."""
from __future__ import annotations
from .lab_score_portable_html_safety import admit_inert_html

_EXPLAIN = {
    "evidence_reused": "Recapture independent first-party synthetic originals",
    "score_drift": "Review isolated synthetic scorer drift",
}
_GATE = ("Qualified independent HUMAN review of original private source, "
         "identity, permissions and source/security/privacy scope.")


def render_action_brief(data: dict, fmt: str) -> str:
    if fmt not in ("actions-brief-markdown", "actions-brief-html"):
        raise ValueError("invalid HUMAN brief format")
    rows = data["actions"]
    if (data["schema"] != "lightup.lab-score-human-two-transport-actions.v1"
            or data["review_status"] not in ("PASS", "HOLD")
            or data["human_review_only"] is not True
            or data["hold_action_rows"] != len(rows)-1
            or not 1 <= len(rows) <= 113
            or any(data[k] is not False for k in (
                "original_source_authenticated", "same_originals_proven",
                "authorization_granted", "remediation_verified", "deployment"))):
        raise ValueError("untrusted original HUMAN actions")
    per_source = {"baseline": [], "candidate": []}
    for item in rows[:-1]:
        origin, reason = item["transport"], item["reason"]
        p, c = item["anonymous_previous"], item["anonymous_current"]
        action = ("RECAPTURE_INDEPENDENT_SYNTHETIC_ORIGINALS"
                  if reason == "evidence_reused"
                  else "REVIEW_ISOLATED_SYNTHETIC_SCORER_DRIFT")
        if (origin not in per_source or reason not in _EXPLAIN
                or type(p) is not int or type(c) is not int
                or not 1 <= p < c <= 8 or item["human_action"] != action
                or item["completion"] != "NOT_VERIFIED"
                or item["authorization_granted"] is not False
                or item["remediation_verified"] is not False):
            raise ValueError("untrusted source-bound HOLD row")
        per_source[origin].append((f"{p}-{c}", _EXPLAIN[reason]))
    gate = rows[-1]
    if (gate["transport"] != "both_independent_origins"
            or gate["reason"] != "original_source_and_identity_unverified"
            or gate["human_action"] != "HUMAN_COMPARE_ORIGINAL_PRIVATE_SOURCES_AND_APPROVALS"
            or gate["anonymous_previous"] is not None
            or gate["anonymous_current"] is not None
            or gate["completion"] != "NOT_VERIFIED"
            or gate["authorization_granted"] is not False
            or gate["remediation_verified"] is not False):
        raise ValueError("missing mandatory independent source gate")
    if fmt == "actions-brief-markdown":
        lines = ["# LightUp synthetic offline HUMAN action brief", "",
                 f"**GLOBAL STATUS {data['review_status']} — NOT VERIFIED / NOT AUTHORIZED**",
                 "", "Independent ZIP ordinals cannot identify matching original sources.", ""]
        for source, tasks in per_source.items():
            lines += [f"## {source.title()} — {len(tasks)} original HOLD actions", ""]
            lines += [f"- [ ] Anonymous pair {pair}: {reason} — NOT_VERIFIED"
                      for pair, reason in tasks]
            if not tasks:
                lines += ["No local HOLD rows; independent source review still required."]
            lines += [""]
        lines += ["## Mandatory independent HUMAN gate", "- [ ] "+_GATE,
                  "", "Previous HOLD is not cleared by a later local PASS.",
                  "No external targets, scans, security grants, research or release.", ""]
        output = "\n".join(lines)
        if not 0 < len(output.encode("utf-8")) <= 65536:
            raise ValueError("oversize HUMAN Markdown brief")
        return output
    blocks = []
    for source, tasks in per_source.items():
        items = "".join(f"<li>Anonymous pair {pair}: {reason} — "
                        "<strong>NOT_VERIFIED</strong></li>" for pair,reason in tasks)
        blocks.append(f"<section id='{source}'><h2>{source.title()} — "
                      f"{len(tasks)} HOLD actions</h2><ul>{items}</ul></section>")
    result = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
              "<meta name='viewport' content='width=device-width, initial-scale=1'>"
              "<meta http-equiv='Content-Security-Policy' "
              "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
              "<title>LightUp offline HUMAN source review brief</title>"
              "<style>body{font:1rem/1.5 system-ui;max-width:62rem;margin:auto;padding:1rem}"
              "section{border:1px solid;padding:1rem;margin:1rem 0}"
              "a:focus{outline:3px solid}@media print{section{break-inside:avoid}}"
              "</style></head><body><main>"
              "<h1>Offline synthetic HUMAN original-source action brief</h1>"
              f"<p><strong>GLOBAL STATUS {data['review_status']}</strong>"
              " — NOT VERIFIED / NOT AUTHORIZED.</p>"
              "<p>Anonymous original ordinals are local to each ZIP. Never"
              " match identities or infer remediation, consent, grant or deployment.</p>"
              "<p>Sections: Baseline · Candidate · Independent HUMAN gate.</p>"
              + "".join(blocks) +
              "<section id='independent'><h2>Mandatory independent HUMAN gate</h2><p>"
              +_GATE+" <strong>NOT_VERIFIED</strong></p></section>"
              "<p>Earlier HOLD is not cleared by later PASS. No scans, grants,"
              " external targets, research or release.</p></main></body></html>")
    if len(result.encode()) > 65536:
        raise ValueError("bounded HTML brief exceeded")
    admit_inert_html(result.encode())
    return result
