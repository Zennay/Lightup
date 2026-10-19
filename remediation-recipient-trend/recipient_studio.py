#!/usr/bin/env python3
"""Build offline editable HUMAN-only workroom from exact native recipient receipt.

This creates only local PRIVATE source-free HUMAN bookkeeping, never accesses
or changes original clients, source evidence, targets, authorization or scan.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
from pathlib import Path
import sys

import receive
import timeline_receive
import trend

review = trend.review
workspace = trend.workspace
triage = trend.triage
board = trend.board
verify = trend.verify

KIND = "lightup.private_recipient_human_reason_studio"
WARNING = (
    "UNVERIFIED private HUMAN recipient notes; original client/source/cohort "
    "authenticity and remediation status UNKNOWN. Counts, timestamps and "
    "notes never authorize or verify a fix, grant, scan or retest."
)
JOURNAL_KIND = "lightup.private_recipient_human_reason_journal"
DISPOSITION = "HUMAN_NOT_ACTION_AUTHORITY"

STYLE = """
:root{color-scheme:light;font:16px system-ui,sans-serif}
body{margin:0;background:#f5f7fb;color:#15263e;line-height:1.55}
header{background:#183555;color:white;padding:1.5rem max(1rem,calc((100vw - 920px)/2))}
main{max-width:920px;margin:auto;padding:1.5rem 1rem}
h1{font-size:1.65rem;margin:0}h2{margin-top:0}h3{font-size:1.06rem}
.summary,.reason,aside{background:white;border-radius:12px;padding:1.3rem;margin:1rem 0;box-shadow:0 1px 7px #142c4220}
aside{border-left:5px solid #b2721f}
label{display:block;font-weight:650;margin:.7rem 0}
select,textarea{display:block;font:inherit;width:100%;max-width:100%;box-sizing:border-box;border:1px solid #99a7b6;border-radius:8px;padding:.6rem;background:white}
select{max-width:460px}
button,.picker{display:inline-block;margin:.5rem .5rem .5rem 0;padding:.7rem 1rem;border-radius:8px;border:1px solid #315276;background:#fff;color:#14365c;font:inherit;cursor:pointer}
button:hover,.picker:hover{background:#e9eff6}
button:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #af671b}
#restore{display:block;margin:.25rem 0 .8rem;max-width:100%}
.reason p{margin:.4rem 0;color:#38506e}
#status{min-height:1.5em;font-weight:700}
small{color:#44556e}
"""

def admit_receipt(path: Path, kind: str) -> tuple[dict, bytes, bytes]:
    review.require(kind in ("compare", "series"),
                   "Source kind must be exact compare or series")
    if kind == "compare":
        receive.inspect(path)
        filename = "counts.json"
    else:
        timeline_receive.inspect(path)
        filename = "series.json"
    manifest = review.private_read(path / "manifest.json")
    raw = review.private_read(path / filename)
    doc = verify.json_obj(raw)
    review.require(raw == workspace.pretty(doc),
                   "Native source-free document must be canonical")
    return doc, manifest, raw


def snapshot_hash(manifest: bytes, raw: bytes) -> str:
    return hashlib.sha256(manifest + b"\x00" + raw).hexdigest()


def reasons_for(doc: dict, kind: str) -> tuple[dict, dict]:
    if kind == "compare":
        current = doc["right"]
        delta = doc["delta_right_minus_left"]
    else:
        current = doc["snapshots"][-1]["counts"]
        delta = doc["adjacent_user_order_deltas"][-1]["delta_right_minus_left"]
    return current["reasons"], delta["reasons"]


def studio_seed(doc: dict, manifest: bytes, raw: bytes, kind: str) -> dict:
    reasons, delta = reasons_for(doc, kind)
    review.require(set(reasons) == set(triage.REASONS) and
                   set(delta) == set(triage.REASONS),
                   "Native HUMAN reason vocabulary mismatch")
    items = []
    for reason in sorted(triage.REASONS):
        review.require(reason in board.ADVICE, "Unknown original HUMAN follow-up")
        items.append({"reason": reason, "count": reasons[reason],
                      "delta": delta[reason], "advice": board.ADVICE[reason]})
    return {"kind": KIND, "schema_version": 1,
            "disposition": DISPOSITION,
            "source_sha256": snapshot_hash(manifest, raw),
            "warning": WARNING, "reasons": items}


def script_hash(source: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(source).digest()).decode("ascii") + "'"


def standalone(seed: dict) -> bytes:
    script = Path(__file__).with_name("recipient_studio.js").read_bytes()
    review.require(b"</script" not in script.lower() and
                   len(script) <= 42000, "Unsafe/missing native private workroom script")
    serialized = json.dumps(seed, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).replace("<", "\\u003c")
    css = STYLE.encode("utf-8")
    policy = ("default-src 'none'; connect-src 'none'; img-src 'none'; "
              "font-src 'none'; media-src 'none'; object-src 'none'; "
              "form-action 'none'; base-uri 'none'; "
              "style-src " + script_hash(css) + "; "
              "script-src " + script_hash(script))
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"" +
            html.escape(policy, quote=True) + "\">"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<title>LightUp PRIVATE HUMAN Recipient Workroom</title>"
            "<style>" + STYLE + "</style></head><body>"
            "<header><h1>LightUp · Private HUMAN Follow-up Workroom</h1>"
            "<p>Local-only reason groups, not evidence or permission.</p></header>"
            "<main><aside><strong>INCUBATE M3/M7 · DRAFT/HOLD.</strong> "
            + html.escape(WARNING) +
            " A count is not an original finding, an owner, or a signed source."
            " Do not paste client IDs, evidence bytes, secrets or targets into notes.</aside>"
            "<section class='summary'><h2>Human-only recipient follow-up</h2>"
            "<p>Assign proposed stages, routing and PRIVATE local notes to aggregate "
            "reason groups. Nothing is sent to original Casework or a live client.</p>"
            "<p id='stats' aria-live='polite'></p>"
            "<button type='button' id='save'>Download PRIVATE HUMAN journal JSON</button>"
            "<label for='restore'>Restore journal from this exact source-free snapshot</label>"
            "<input type='file' id='restore' accept='.json,application/json'>"
            "<button type='button' id='reset'>Reset local draft</button>"
            "<p id='status' role='status' aria-live='polite'></p></section>"
            "<div id='rows'></div><section class='summary'><h2>Important boundary</h2>"
            "<p>This tool does not authenticate client identities, consent, original "
            "evidence, chronology, an authorized scan or actual remediation. "
            "An exported journal is PRIVATE and requires original native Python "
            "admission before further local presentation.</p></section></main>"
            "<script id='source-seed' type='application/json'>" + serialized + "</script>"
            "<script>" + script.decode("utf-8") + "</script>"
            "</body></html>\n").encode("utf-8")


def artifacts(seed: dict) -> dict[str, bytes]:
    return {"index.html": standalone(seed),
            "source-free.json": workspace.pretty(seed)}


def publish(receipt: Path, kind: str, output: Path) -> dict:
    review.require(output.is_absolute() and output != receipt and
                   receipt not in output.parents and
                   output not in receipt.parents and
                   output.parent != receipt and
                   output.parent == output.parent.resolve(strict=True),
                   "PRIVATE recipient workroom cannot modify its original receipt")
    triage.private_parent(output)
    doc, manifest_raw, source_raw = admit_receipt(receipt, kind)
    seed = studio_seed(doc, manifest_raw, source_raw, kind)
    docs = artifacts(seed)
    manifest = {"kind": KIND + ".local_receipt", "schema_version": 1,
                "disposition": DISPOSITION,
                **{flag: False for flag in review.FLAGS},
                "warning": WARNING,
                "files": {name: {"bytes": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in sorted(docs.items())}}
    _, current_manifest, current_raw = admit_receipt(receipt, kind)
    review.require(current_manifest == manifest_raw and current_raw == source_raw,
                   "Original source-free receipt changed while building workroom")
    workspace.publish_bundle(output, docs, workspace.pretty(manifest))
    return {"human_reason_groups": len(seed["reasons"]),
            "source_kind": kind, "private_files": len(docs) + 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Create a PRIVATE source-bound offline HUMAN recipient reason workroom "
        "from an already native-admitted anonymous comparison or series receipt"))
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--kind", choices=("compare", "series"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = publish(args.receipt, args.kind, args.output_dir)
        print("REVIEW_ONLY: PRIVATE local interactive HUMAN-only workroom created, " +
              str(result["human_reason_groups"]) +
              " aggregate follow-up reasons, no original client/case identity.")
        print("Open private index.html locally. Download PRIVATE journal explicitly.")
        return 2
    except (review.Hold, OSError, ValueError, UnicodeError):
        print("HOLD: original source-free receipt or private workroom cannot be admitted.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
