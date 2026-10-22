#!/usr/bin/env python3
"""Produce a PRIVATE no-network HUMAN worksheet editor from an admitted original packet."""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
import os
import sys

from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import (
    load_json, read_original_bundle, require_private_file, validate_worksheet,
)

NAME = "lightup-lab-human-editor.html"
STYLE = """*{box-sizing:border-box}body{margin:0;background:#f2f5f9;color:#152235;font:16px/1.55 system-ui,sans-serif}
header,main,footer{max-width:1060px;margin:auto;padding:1.2rem}h1{font-size:clamp(1.75rem,4vw,2.6rem)}
.status{border-left:6px solid #9a5b18;background:#fff5e7;padding:.8rem;font-weight:800}
.panel{background:white;border:1px solid #d8e1ea;border-radius:.7rem;padding:1rem;margin:1.2rem 0}
article{border-top:1px solid #e0e5ec;padding:1rem 0}label{display:block;font-weight:700;margin:.45rem 0}
select,textarea{display:block;width:100%;font:inherit;padding:.6rem;border:1px solid #8899ac;border-radius:.4rem}
textarea{min-height:5.5rem;resize:vertical}select{max-width:24rem}
button{font:inherit;font-weight:800;padding:.8rem 1.2rem;background:#1c3a62;color:white;border:0;border-radius:.45rem;cursor:pointer}
button:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #edb64e;outline-offset:2px}
.note{font-size:.92rem;color:#46566a}#message{font-weight:800;min-height:1.7rem}
@media(max-width:640px){header,main,footer{padding:.75rem}.panel{padding:.8rem}}"""
SCRIPT = r'''"use strict";
(() => {
  const encoded = __DATA64__;
  const data = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(
    Uint8Array.from(atob(encoded), x => x.charCodeAt(0))));
  const stages = ["NEEDS_INPUT", "HUMAN_REVIEW", "FOLLOW_UP"];
  const roles = ["UNASSIGNED", "LAB_OPERATOR", "SCOPE_OWNER", "SECURITY_REVIEWER", "PRIVACY_REVIEWER"];
  const list = document.getElementById("rows");
  const count = document.getElementById("count");
  const message = document.getElementById("message");
  const button = document.getElementById("export");
  if (!Array.isArray(data.human_rows) || data.human_rows.length < 1 ||
      data.human_rows.length > 16 ||
      data.human_rows.length !== data.source_endpoint_count ||
      !Number.isSafeInteger(data.source_endpoint_count)) {
    message.textContent = "Source-bound worksheet is not a bounded HUMAN planning file.";
    return;
  }
  function field(label, control) {
    const wrap = document.createElement("label");
    wrap.textContent = label;
    wrap.append(control);
    return wrap;
  }
  function select(options, value, onChange) {
    const element = document.createElement("select");
    for (const valueOfOption of options) {
      const option = document.createElement("option");
      option.value = valueOfOption;
      option.textContent = valueOfOption.replaceAll("_", " ");
      element.append(option);
    }
    element.value = value;
    element.addEventListener("change", () => onChange(element.value));
    return element;
  }
  for (const [index, row] of data.human_rows.entries()) {
    if (!row || row.slot !== index + 1 || !stages.includes(row.stage) ||
        !roles.includes(row.role) || typeof row.note !== "string" ||
        row.note.length > 400) {
      message.textContent = "Invalid original row schema; native CLI admission is required.";
      list.replaceChildren();
      return;
    }
    const block = document.createElement("article");
    const heading = document.createElement("h3");
    heading.textContent = "Endpoint slot " + String(row.slot).padStart(2, "0");
    block.append(heading);
    block.append(field("HUMAN follow-up stage",
      select(stages, row.stage, value => { row.stage = value; message.textContent = "Unsaved changes in memory."; })));
    block.append(field("Suggested human reviewer role",
      select(roles, row.role, value => { row.role = value; message.textContent = "Unsaved changes in memory."; })));
    const note = document.createElement("textarea");
    note.maxLength = 400;
    note.value = row.note;
    note.autocomplete = "off";
    note.setAttribute("aria-label", "Private HUMAN note for endpoint slot " + row.slot);
    note.addEventListener("input", () => { row.note = note.value; message.textContent = "Unsaved changes in memory."; });
    block.append(field("PRIVATE HUMAN note (max 400 characters)", note));
    list.append(block);
  }
  count.textContent = data.human_rows.length + " source-bound HUMAN slots; no endpoint values loaded.";
  button.disabled = false;
  button.addEventListener("click", () => {
    const denied = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u2069]/u;
    if (data.human_rows.some(row => row.note.length > 400 || denied.test(row.note))) {
      message.textContent = "A HUMAN note contains disallowed controls or exceeds 400 characters.";
      return;
    }
    // Never edit flags, source digest, identity, slots, or original producer fields.
    const raw = JSON.stringify(data, null, 2) + "\n";
    if (new Blob([raw]).size > 32768) {
      message.textContent = "Private worksheet exceeds the native size bound.";
      return;
    }
    const url = URL.createObjectURL(new Blob([raw], {type:"application/json;charset=utf-8"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = "lightup-lab-human-private.edited.json";
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2500);
    message.textContent = "PRIVATE JSON downloaded. Move into a mode-0700 owner-only folder, chmod 600, then re-admit through review_desk.py --responses. This is not approval.";
  });
})();'''
def render_editor(work):
    # UTF-8 source is encoded inside hash-pinned inline JS. No untrusted data is
    # inserted as markup, URLs or HTML attributes.
    payload = base64.b64encode(json.dumps(
        work, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).decode("ascii")
    script = SCRIPT.replace("__DATA64__", json.dumps(payload))
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    script_hash = base64.b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " script-src 'sha256-" + script_hash + "'; style-src 'sha256-" + style_hash +
        "'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none';"
        " form-action 'none'; frame-src 'none'; worker-src 'none'\">"
        "<title>LightUp · PRIVATE HUMAN worksheet editor</title><style>" + STYLE +
        "</style></head><body><header><p>LIGHTUP / OFFLINE HUMAN-ONLY WORKSPACE</p>"
        "<h1>Source-bound HUMAN follow-up editor</h1>"
        "<p class='status'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY · "
        "NOT AUTHORIZED</p></header><main><section class='panel'>"
        "<p>This private local file contains your source-bound HUMAN notes and manifest "
        "fingerprint. Never host or share it. No external assets, browser storage, "
        "DNS, network or assessment execution.</p>"
        "<p>The original endpoint URLs are not embedded. Only the pinned native "
        "Launchpad/review desk can independently re-admit the exact original source. "
        "Changes made here are local HUMAN proposals, not clearance or consent.</p>"
        "<p id='count' class='note' role='status'></p>"
        "<div id='rows'></div><button id='export' type='button' disabled>"
        "Download edited PRIVATE HUMAN JSON</button><p id='message' role='status' "
        "aria-live='polite'></p><p class='note'>Browser downloads cannot enforce "
        "mode 0600. Re-open the changed worksheet in a private mode-0700 folder "
        "through review_desk.py --responses to apply native schema/source validation. "
        "HUMAN GO, independent security/privacy reviews, authentic client/operator "
        "consent and revocation remain separate mandatory gates.</p>"
        "</section></main><footer><p class='note'>No original endpoint/target "
        "values, command execution, grants or network requests.</p></footer>"
        "<script>" + script + "</script></body></html>"
    ).encode("utf-8")

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Create a portable PRIVATE HUMAN editor; no assessment, network or grant."))
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--responses", required=True, help="owner-private HUMAN JSON worksheet")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", help="new separate owner-private mode-0700 directory")
    mode.add_argument("--verify-editor-dir", help="read-only reopen existing private editor")
    parser.add_argument("--explain-hold", action="store_true",
                        help="print the curated non-sensitive HOLD reason; never prints paths, endpoint values or raw exceptions")
    args = parser.parse_args(argv)
    try:
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        worksheet = os.path.abspath(os.fspath(args.responses))
        work = load_json(require_private_file(worksheet))
        validate_worksheet(work, digest, len(endpoints))
        folder = args.output_dir or args.verify_editor_dir
        fd, dest = open_output_directory(folder)
        try:
            for source in (original, os.path.dirname(worksheet)):
                if os.path.commonpath((source, dest)) in (source, dest):
                    raise Hold("PRIVATE editor output must be separate from source files")
            content = render_editor(work)
            if args.verify_editor_dir:
                if set(os.listdir(fd)) != {NAME}:
                    raise Hold("PRIVATE HUMAN editor directory has missing or unexpected files")
                existing = read_private_bundle_item(fd, NAME, 131072)
                if existing != content:
                    raise Hold("PRIVATE editor changed or no longer source-bound")
            else:
                if os.listdir(fd):
                    raise Hold("new PRIVATE HUMAN editor directory must be empty")
                # Re-admit source and worksheet before publication, without network.
                later_original, later_endpoints, later_digest = read_original_bundle(args.bundle_dir)
                later_work = load_json(require_private_file(worksheet))
                validate_worksheet(later_work, later_digest, len(later_endpoints))
                if ((later_original, later_endpoints, later_digest, later_work) !=
                        (original, endpoints, digest, work)):
                    raise Hold("source or HUMAN worksheet drifted while composing editor")
                publish_bundle(fd, [(NAME, content)])
        finally:
            os.close(fd)
        print("HUMAN_EDITOR_" + ("REOPENED" if args.verify_editor_dir else "CREATED") +
              " — PRIVATE LOCAL ONLY, UNSIGNED; NOT AUTHORIZED")
        return 0
    except Hold as error:
        report_hold("HUMAN_EDITOR_HOLD — original packet or HUMAN source could not be admitted",
                    error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError, OverflowError):
        report_hold("HUMAN_EDITOR_HOLD — original packet or HUMAN source could not be admitted",
                    None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
