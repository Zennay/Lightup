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
    css = CSS.read_bytes()
    html = TEMPLATE.read_text(encoding="utf-8")
    engine_tag = '<script src="../casework/remediation-engine.js"></script>'
    script_tag = '<script src="./history-studio.js"></script>'
    checkpoint_tag = '<script src="./private-checkpoint.js"></script>'
    pair_tag = '<script src="./source-pair-diff.js"></script>'
    native_tag = '<script src="./native-casework-bridge.js"></script>'
    human_tag = '<script src="./human-casework-desk.js"></script>'
    calendar_tag = '<script src="./human-workload-calendar.js"></script>'
    css_tag = '<link rel="stylesheet" href="./studio.css">'
    csp_start = '<meta http-equiv="Content-Security-Policy" content="'
    start = html.index(csp_start)
    end = html.index('">', start)
    csp = (
        "default-src 'none'; script-src 'sha256-" + sha(engine) +
        "' 'sha256-" + sha(js) + "' 'sha256-" + sha(checkpoint) + "' 'sha256-" + sha(pair_diff) + "' 'sha256-" + sha(native_casework) + "' 'sha256-" + sha(human_desk) + "' 'sha256-" + sha(human_calendar) + "'; style-src 'sha256-" +
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
    ):
        if html.count(search) != 1:
            raise SystemExit("HOLD: original HTML asset reference missing/duplicated")
        html = html.replace(search, replacement)
    OUTPUT.write_text(html, encoding="utf-8")
    data = OUTPUT.read_bytes()
    print(f"Built {OUTPUT.relative_to(ROOT)}: {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")

if __name__ == "__main__":
    main()
