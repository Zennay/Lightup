#!/usr/bin/env python3
"""Build one offline CSP SHA-pinned HTML from the ORIGINAL unchanged Casework parser.
Source generation only; no QA/tests, scans, network access or authorization.
"""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ENGINE = ROOT / "casework" / "remediation-engine.js"
EXPECTED_ENGINE_SHA256 = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
SCRIPT = HERE / "history-studio.js"
CHECKPOINT = HERE / "private-checkpoint.js"
PAIR_DIFF = HERE / "source-pair-diff.js"
NATIVE_CASEWORK = HERE / "native-casework-bridge.js"
HUMAN_DESK = HERE / "human-casework-desk.js"
HUMAN_CALENDAR = HERE / "human-workload-calendar.js"
HUMAN_INTERVENTION = HERE / "human-intervention-brief.js"
BULK_SOURCE_CARRY = HERE / "bulk-source-carry.js"
HUMAN_HOLD_REVIEW = HERE / "human-hold-review.js"
PRIVATE_SOURCE_RECOVERY = HERE / "private-source-recovery.js"
PRIVATE_SOURCE_REIMPORT = HERE / "private-source-reimport.js"
PRIVATE_DECISION_LEDGER = HERE / "private-decision-ledger.js"
PRIVATE_FINDING_DOSSIER = HERE / "private-finding-dossier.js"
CSS = HERE / "studio.css"
TEMPLATE = HERE / "index.html"
OUTPUT = HERE / "standalone.html"

def sha(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")

def main() -> None:
    engine = ENGINE.read_bytes()
    if hashlib.sha256(engine).hexdigest() != EXPECTED_ENGINE_SHA256:
        raise SystemExit("HOLD: original source owner parser bytes changed")
    js = SCRIPT.read_bytes()
    checkpoint = CHECKPOINT.read_bytes()
    pair_diff = PAIR_DIFF.read_bytes()
    native_casework = NATIVE_CASEWORK.read_bytes()
    human_desk = HUMAN_DESK.read_bytes()
    human_calendar = HUMAN_CALENDAR.read_bytes()
    human_intervention = HUMAN_INTERVENTION.read_bytes()
    bulk_source_carry = BULK_SOURCE_CARRY.read_bytes()
    human_hold_review = HUMAN_HOLD_REVIEW.read_bytes()
    private_source_recovery = PRIVATE_SOURCE_RECOVERY.read_bytes()
    private_source_reimport = PRIVATE_SOURCE_REIMPORT.read_bytes()
    private_decision_ledger = PRIVATE_DECISION_LEDGER.read_bytes()
    private_finding_dossier = PRIVATE_FINDING_DOSSIER.read_bytes()
    css = CSS.read_bytes()
    html = TEMPLATE.read_text(encoding="utf-8")
    engine_tag = '<script src="../casework/remediation-engine.js"></script>'
    script_tag = '<script src="./history-studio.js"></script>'
    checkpoint_tag = '<script src="./private-checkpoint.js"></script>'
    pair_tag = '<script src="./source-pair-diff.js"></script>'
    native_tag = '<script src="./native-casework-bridge.js"></script>'
    human_tag = '<script src="./human-casework-desk.js"></script>'
    calendar_tag = '<script src="./human-workload-calendar.js"></script>'
    intervention_tag = '<script src="./human-intervention-brief.js"></script>'
    bulk_carry_tag = '<script src="./bulk-source-carry.js"></script>'
    hold_review_tag = '<script src="./human-hold-review.js"></script>'
    recovery_tag = '<script src="./private-source-recovery.js"></script>'
    reimport_tag = '<script src="./private-source-reimport.js"></script>'
    decision_ledger_tag = '<script src="./private-decision-ledger.js"></script>'
    dossier_tag = '<script src="./private-finding-dossier.js"></script>'
    css_tag = '<link rel="stylesheet" href="./studio.css">'
    csp_start = '<meta http-equiv="Content-Security-Policy" content="'
    start = html.index(csp_start)
    end = html.index('">', start)
    csp = (
        "default-src 'none'; script-src 'sha256-" + sha(engine) +
        "' 'sha256-" + sha(js) + "' 'sha256-" + sha(checkpoint) + "' 'sha256-" + sha(pair_diff) + "' 'sha256-" + sha(native_casework) + "' 'sha256-" + sha(human_desk) + "' 'sha256-" + sha(human_calendar) + "' 'sha256-" + sha(human_intervention) + "' 'sha256-" + sha(bulk_source_carry) + "' 'sha256-" + sha(human_hold_review) + "' 'sha256-" + sha(private_source_recovery) + "' 'sha256-" + sha(private_source_reimport) + "' 'sha256-" + sha(private_decision_ledger) + "' 'sha256-" + sha(private_finding_dossier) + "'; style-src 'sha256-" +
        sha(css) + "'; img-src 'none'; font-src 'none'; connect-src 'none'; "
        "form-action 'none'; base-uri 'none'; object-src 'none'"
    )
    html = html[:start] + csp_start + csp + html[end:]
    for search, replacement in (
        (css_tag, "<style>" + css.decode("utf-8") + "</style>"),
        (engine_tag, "<script>" + engine.decode("utf-8") + "</script>"),
        (script_tag, "<script>" + js.decode("utf-8") + "</script>"),
        (checkpoint_tag, "<script>" + checkpoint.decode("utf-8") + "</script>"),
        (pair_tag, "<script>" + pair_diff.decode("utf-8") + "</script>"),
        (native_tag, "<script>" + native_casework.decode("utf-8") + "</script>"),
        (human_tag, "<script>" + human_desk.decode("utf-8") + "</script>"),
        (calendar_tag, "<script>" + human_calendar.decode("utf-8") + "</script>"),
        (intervention_tag, "<script>" + human_intervention.decode("utf-8") + "</script>"),
        (bulk_carry_tag, "<script>" + bulk_source_carry.decode("utf-8") + "</script>"),
        (hold_review_tag, "<script>" + human_hold_review.decode("utf-8") + "</script>"),
        (recovery_tag, "<script>" + private_source_recovery.decode("utf-8") + "</script>"),
        (reimport_tag, "<script>" + private_source_reimport.decode("utf-8") + "</script>"),
        (decision_ledger_tag, "<script>" + private_decision_ledger.decode("utf-8") + "</script>"),
        (dossier_tag, "<script>" + private_finding_dossier.decode("utf-8") + "</script>"),
    ):
        if html.count(search) != 1:
            raise SystemExit("HOLD: original HTML asset reference missing/duplicated")
        html = html.replace(search, replacement)
    OUTPUT.write_text(html, encoding="utf-8")
    data = OUTPUT.read_bytes()
    print(f"Built {OUTPUT.relative_to(ROOT)}: {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")

if __name__ == "__main__":
    main()
