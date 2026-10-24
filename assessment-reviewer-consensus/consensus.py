"""Private, offline, original-byte-bound HUMAN plan reconciliation. Never authority."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import sys

MAX_BYTES = 3 * 1024 * 1024
PLAN_KIND = "lightup.private_original_lab_human_matrix_plan"
PLAN_KEYS = frozenset(("kind", "version", "disposition", "authorized", "consent_verified",
    "dispatch_allowed", "release_allowed", "source_sha256", "ordered_row_count",
    "row_plans", "interpretation"))
FALSE_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
ENUMS = {
    "stage": ("needs_review", "queued", "discussing", "documented", "blocked"),
    "route": ("unassigned", "scope", "findings", "evidence", "remediation", "privacy"),
    "action": ("none", "clarify_source", "review_scope_policy", "request_evidence_review",
        "discuss_declared_difference", "prepare_private_human_brief",
        "request_independent_human_review"),
}
DEFAULT = {"stage": "needs_review", "route": "unassigned", "action": "none"}
ROWS = frozenset(("ordinal", "stage", "route", "action"))
DIGEST = frozenset("0123456789abcdef")
RESOLUTION_KEYS = frozenset(("kind", "version", "input_sha256", "source_sha256",
    "ordered_row_count", "resolutions"))
RESOLUTION_ROW_KEYS = frozenset(("ordinal", "field", "choices", "value"))


class Hold(ValueError):
    """Input is not admissible: never publish a merged HUMAN plan."""


def require(ok: bool, why: str) -> None:
    if not ok:
        raise Hold(why)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object member")
        result[key] = value
    return result


def exact(obj, fields) -> bool:
    return type(obj) is dict and set(obj) == set(fields)


def digest(value) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= DIGEST


def integer(value, lower, upper) -> bool:
    return type(value) is int and lower <= value <= upper


def read_private(path: Path, limit: int = MAX_BYTES):
    # Refuse symlink and other non-ordinary path tricks before reading user files.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "input is not a regular private file")
        require(0 < info.st_size <= limit, "input exceeds private byte limit")
        # Original HUMAN plans may contain source digests and sensitive workflow choices.
        require(info.st_mode & 0o077 == 0, "private input must not be accessible by group/others (chmod 600)")
        raw = os.read(fd, limit + 1)
        require(len(raw) == info.st_size, "file changed while being read")
        after = os.fstat(fd)
        require(after.st_size == info.st_size and after.st_mtime_ns == info.st_mtime_ns
            and after.st_ino == info.st_ino and after.st_dev == info.st_dev,
            "file identity or contents changed during admission")
    finally:
        os.close(fd)
    try:
        content = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(Hold("nonfinite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Hold("malformed private UTF-8 JSON") from exc
    return raw, content


def admit_plan(value):
    require(exact(value, PLAN_KEYS), "incorrect original PRIVATE plan structure")
    require(value["kind"] == PLAN_KIND and type(value["version"]) is int
        and value["version"] == 1 and value["disposition"] == "REVIEW_ONLY_DRAFT_HOLD",
        "unsupported original plan version/disposition")
    require(all(value[key] is False for key in FALSE_FLAGS), "authority flag is not false")
    sources = value["source_sha256"]
    require(type(sources) is list and 2 <= len(sources) <= 8
        and all(digest(item) for item in sources), "invalid original-byte source binding")
    n = value["ordered_row_count"]
    require(integer(n, 1, 16384), "invalid original ordered row count")
    require(type(value["interpretation"]) is str
        and 1 <= len(value["interpretation"]) <= 1024, "invalid HUMAN interpretation")
    entries = value["row_plans"]
    require(type(entries) is list and len(entries) <= n, "invalid sparse HUMAN rows")
    expanded = [{**DEFAULT} for _ in range(n)]
    last = 0
    for entry in entries:
        require(exact(entry, ROWS), "incorrect sparse row structure")
        ordinal = entry["ordinal"]
        require(integer(ordinal, 1, n) and ordinal > last,
            "HUMAN row ordinals must increase uniquely")
        require(all(type(entry[field]) is str and entry[field] in choices
            for field, choices in ENUMS.items()), "invalid HUMAN selection")
        require(any(entry[field] != DEFAULT[field] for field in ENUMS),
            "default-only entry must not be serialized")
        expanded[ordinal - 1] = {field: entry[field] for field in ENUMS}
        last = ordinal
    return sources, n, expanded


def reconcile(plans):
    sources, n, _first = plans[0]
    require(all(src == sources and count == n for src, count, _ in plans),
        "different original source bytes, order, or row count: entire batch HOLD")
    merged = [{**DEFAULT} for _ in range(n)]
    conflicts = []
    contributed = 0
    for i in range(n):
        for field in ENUMS:
            submitted = sorted({rows[i][field] for _src, _n, rows in plans
                if rows[i][field] != DEFAULT[field]})
            if not submitted:
                continue
            contributed += 1
            if len(submitted) > 1:
                conflicts.append({"ordinal": i + 1, "field": field,
                    "choices": submitted, "value": None})
            else:
                merged[i][field] = submitted[0]
    return merged, conflicts, contributed


def admit_resolutions(packet, sources, n, fingerprints, conflicts):
    require(exact(packet, RESOLUTION_KEYS), "invalid resolution packet")
    require(packet["kind"] == "lightup.private_lab_human_conflicts"
        and type(packet["version"]) is int and packet["version"] == 1,
        "invalid resolution version")
    require(packet["source_sha256"] == sources
        and packet["input_sha256"] == fingerprints
        and type(packet["ordered_row_count"]) is int
        and packet["ordered_row_count"] == n, "stale or reordered source/reviewer inputs")
    entries = packet["resolutions"]
    require(type(entries) is list and len(entries) == len(conflicts),
        "every original conflicting selection must have exactly one resolution")
    decisions = {}
    for given, expected in zip(entries, conflicts):
        require(exact(given, RESOLUTION_ROW_KEYS)
            and given["ordinal"] == expected["ordinal"]
            and given["field"] == expected["field"]
            and given["choices"] == expected["choices"],
            "conflict item, ordering or original choices changed")
        require(type(given["value"]) is str and given["value"] in expected["choices"],
            "select one original HUMAN choice for each conflict")
        decisions[(expected["ordinal"], expected["field"])] = given["value"]
    return decisions


def interactive_decisions(conflicts):
    require(sys.stdin.isatty() and sys.stdout.isatty(),
        "interactive HUMAN resolution requires a foreground terminal")
    require(len(conflicts) <= 512,
        "too many interactive conflicts: use the bounded PRIVATE resolution packet instead")
    print("PRIVATE HUMAN proposals, not scan decisions, identity, evidence or authorization.")
    print("Select each original submitted choice; Ctrl-C cancels without publication.")
    result = {}
    for item in conflicts:
        print("\nSource-local row", item["ordinal"], "| HUMAN", item["field"])
        for i, choice in enumerate(item["choices"], 1):
            print(" ", i, "—", choice)
        try:
            answer = input("Enter an option number: ").strip()
        except EOFError as exc:
            raise Hold("interactive reconciliation cancelled") from exc
        require(answer.isascii() and answer.isdecimal()
            and 1 <= int(answer) <= len(item["choices"]),
            "invalid HUMAN conflict choice; entire merge HOLD")
        result[(item["ordinal"], item["field"])] = item["choices"][int(answer) - 1]
    try:
        confirm = input("Type PROPOSE to write a PRIVATE HUMAN draft (never authorize): ")
    except EOFError as exc:
        raise Hold("interactive confirmation not received") from exc
    require(confirm == "PROPOSE", "operator did not confirm proposal")
    return result


def write_new(directory: Path, name: str, data: bytes):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(directory / name, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        (directory / name).unlink(missing_ok=True)
        raise


def json_bytes(data) -> bytes:
    return (json.dumps(data, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def make_review_html(conflicts, source_count, row_count):
    rows = "".join("<tr><td>" + str(item["ordinal"]) + "</td><td>"
        + html.escape(item["field"]) + "</td><td>"
        + html.escape(" / ".join(item["choices"]))
        + "</td><td>Unresolved: edit the matching PRIVATE JSON resolution value</td></tr>"
        for item in conflicts)
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · PRIVATE HUMAN review</title></head><body>
<h1>LightUp · PRIVATE multi-reviewer HUMAN conflict desk</h1>
<p><strong>REVIEW ONLY · DRAFT/HOLD · NO CONSENT, AUTHORIZATION, SCAN OR VERIFIED FINDINGS.</strong></p>
<p>Offline unsigned source-byte-bound inputs. This workroom is not proof of independent reviewer identity.
No original source labels, evidence, target literals or identifiers are shown. Even counts may be private.</p>"""
        + "<p>Original source files: " + str(source_count)
        + " · original HUMAN row slots: " + str(row_count)
        + " · unresolved field conflicts: " + str(len(conflicts)) + "</p>"
        + "<table border=1 cellpadding=8><thead><tr><th>Source-local row</th><th>HUMAN field</th><th>Competing values</th><th>Action</th></tr></thead><tbody>"
        + rows + "</tbody></table><p>To complete the reconciliation, edit only the null <code>value</code>"
        + " fields in private-resolutions.json, then rerun with --resolutions and a NEW output directory."
        + " Conflicts are never silently overwritten. No security or remediation conclusion is implied.</p>"
        + "</body></html>\n").encode("utf-8")



def make_browser_resolver() -> bytes:
    """Offline local-only HUMAN decisions editor; native CLI remains final admission."""
    import base64

    script = r"""(function () {
"use strict";
const KEYSET = ["kind", "version", "input_sha256", "source_sha256",
  "ordered_row_count", "resolutions"];
const FIELD_ORDER = ["stage", "route", "action"];
const OPTIONS = {
  stage: ["needs_review", "queued", "discussing", "documented", "blocked"],
  route: ["unassigned", "scope", "findings", "evidence", "remediation", "privacy"],
  action: ["none", "clarify_source", "review_scope_policy", "request_evidence_review",
    "discuss_declared_difference", "prepare_private_human_brief",
    "request_independent_human_review"]
};
const $ = id => document.getElementById(id);
let packet = null;
const hasOnly = (obj, keys) => obj !== null && typeof obj === "object" &&
  !Array.isArray(obj) && Object.keys(obj).length === keys.length &&
  keys.every(key => Object.hasOwn(obj, key));
const hex = value => typeof value === "string" && value.length === 64 &&
  Array.from(value).every(ch => "0123456789abcdef".includes(ch));
const digestList = a => Array.isArray(a) && a.length >= 2 && a.length <= 8 &&
  a.every(hex);
function message(value, error) {
  $("status").textContent = value;
  $("status").setAttribute("role", error ? "alert" : "status");
}
function forget() {
  packet = null;
  $("save").disabled = true;
  $("rows").replaceChildren();
  $("progress").textContent = "No PRIVATE conflict packet loaded.";
}
function admit(p) {
  if (!hasOnly(p, KEYSET) ||
      p.kind !== "lightup.private_lab_human_conflicts" || p.version !== 1 ||
      !digestList(p.input_sha256) || !digestList(p.source_sha256) ||
      !Number.isInteger(p.ordered_row_count) ||
      p.ordered_row_count < 1 || p.ordered_row_count > 16384 ||
      !Array.isArray(p.resolutions) || p.resolutions.length > 512)
    throw Error("Only bounded original PRIVATE conflict packets with at most 512 fields are supported here.");
  const seen = new Set();
  let previousOrdinal = 0;
  let previousField = "";
  for (const row of p.resolutions) {
    if (!hasOnly(row, ["ordinal", "field", "choices", "value"]) ||
        !Number.isInteger(row.ordinal) || row.ordinal < 1 ||
        row.ordinal > p.ordered_row_count ||
        !Object.hasOwn(OPTIONS, row.field) ||
        !Array.isArray(row.choices) || row.choices.length < 2 ||
        !row.choices.every((choice, i) =>
          typeof choice === "string" && OPTIONS[row.field].includes(choice) &&
          (i === 0 || row.choices[i-1] < choice)) ||
        !(row.value === null || row.choices.includes(row.value)) ||
        (row.ordinal < previousOrdinal) ||
        (row.ordinal === previousOrdinal &&
          FIELD_ORDER.indexOf(row.field) <= FIELD_ORDER.indexOf(previousField)))
      throw Error("Noncanonical original HUMAN conflict item; use the native CLI.");
    const marker = String(row.ordinal) + ":" + row.field;
    if (seen.has(marker)) throw Error("Duplicate PRIVATE conflict field.");
    seen.add(marker);
    previousOrdinal = row.ordinal;
    previousField = row.field;
  }
  return p;
}
function refresh() {
  if (!packet) return;
  const count = packet.resolutions.filter(item => item.value !== null).length;
  $("progress").textContent = count + " / " + packet.resolutions.length +
    " HUMAN fields selected; this editor does not authenticate the original inputs.";
  $("save").disabled = count !== packet.resolutions.length;
}
function render(p) {
  packet = p;
  const table = $("rows");
  table.replaceChildren();
  for (const item of packet.resolutions) {
    const row = document.createElement("tr");
    const ordinal = document.createElement("td");
    ordinal.textContent = String(item.ordinal);
    const field = document.createElement("td");
    field.textContent = item.field;
    const choice = document.createElement("td");
    const select = document.createElement("select");
    select.setAttribute("aria-label", "Original row " + item.ordinal + " HUMAN " + item.field);
    const empty = document.createElement("option");
    empty.value = "";
    empty.textContent = "Choose explicitly";
    select.append(empty);
    for (const value of item.choices) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value.replaceAll("_", " ");
      select.append(option);
    }
    select.value = item.value === null ? "" : item.value;
    select.addEventListener("change", () => {
      item.value = select.value || null;
      refresh();
    });
    choice.append(select);
    row.append(ordinal, field, choice);
    table.append(row);
  }
  refresh();
}
$("load").addEventListener("change", async event => {
  forget();
  try {
    const file = event.target.files[0];
    if (!file || file.size < 1 || file.size > 3 * 1024 * 1024)
      throw Error("Select one original PRIVATE conflict packet up to 3 MiB.");
    const text = new TextDecoder("utf-8", {fatal: true}).decode(await file.arrayBuffer());
    render(admit(JSON.parse(text)));
    message("PRIVATE packet opened in memory only. Original byte-bound CLI re-admission is still mandatory.", false);
  } catch (error) {
    forget();
    message(error.message || "Cannot open PRIVATE packet.", true);
  } finally {
    event.target.value = "";
  }
});
$("save").addEventListener("click", () => {
  if (!packet || packet.resolutions.some(item => item.value === null)) return;
  if (!window.confirm("Save only a PRIVATE unsigned HUMAN choice proposal? Revalidate it with the native CLI; this does not authorize anything.")) return;
  const data = new Blob([JSON.stringify(packet, null, 2) + "\n"],
    {type: "application/json"});
  const url = URL.createObjectURL(data);
  const link = document.createElement("a");
  link.href = url;
  link.download = "private-completed-human-resolutions.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  message("Saved locally. Restrict the downloaded file to owner-only permissions (chmod 600) before native CLI review.", false);
});
})();"""
    css = """body{font:16px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;background:#111a2b;color:#f0f4fa}h1{font-size:1.8rem}strong{color:#ffd98b}p{max-width:90ch}section{padding:1.3rem;background:#1c293d;border-radius:12px;margin:1.2rem 0}input,select,button{font:inherit;padding:.5rem;max-width:100%}button{cursor:pointer}button:disabled{opacity:.5}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.65rem;border-bottom:1px solid #64748b}a{color:#bfdfff}@media(max-width:700px){body{margin:0}th,td{padding:.35rem;font-size:.9rem}}"""
    js_hash = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    css_hash = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; script-src 'sha256-" + js_hash +
        "'; style-src 'sha256-" + css_hash +
        "'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'")
    page = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">'
        '<title>LightUp PRIVATE HUMAN conflict editor</title><style>' + css +
        '</style></head><body><h1>LightUp · PRIVATE HUMAN conflict editor</h1>'
        '<p><strong>REVIEW ONLY / DRAFT HOLD. No grant, scanner, authenticated actor, consent, verified finding or remediation.</strong></p>'
        '<p>Open only an existing PRIVATE conflicts file produced by consensus.py. Choices are local in memory.'
        ' No HTTP, external scripts, browser storage or background service. This editor DOES NOT establish'
        ' input validity or source identity: the original native CLI must re-admit exact original plan bytes.</p>'
        '<section><label for="load">Load PRIVATE conflict JSON</label> '
        '<input id="load" type="file" accept=".json,application/json">'
        '<p id="status" role="status">No PRIVATE packet loaded.</p>'
        '<p id="progress">No PRIVATE conflict packet loaded.</p>'
        '<button id="save" type="button" disabled>Download completed PRIVATE resolutions</button></section>'
        '<section><table><thead><tr><th>Original row ordinal</th><th>HUMAN field</th>'
        '<th>Original reviewer choices</th></tr></thead><tbody id="rows"></tbody></table></section>'
        '<p>Next: chmod 600 on the downloaded file, then run the original consensus.py --resolutions'
        ' with unchanged original reviewer plan files in the same order and a NEW --output directory.'
        ' Small cohort details and source fingerprints are private. Source SHA is not a signature.</p>'
        '<script>' + script + '</script></body></html>\n')
    return page.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Offline PRIVATE source-bound 2–8 HUMAN reviewer plan reconciliation")
    parser.add_argument("plans", nargs="+", type=Path, help="original LightUp PRIVATE HUMAN plan files (chmod 600)")
    parser.add_argument("--output", type=Path, required=True, help="new exclusive private review directory")
    parser.add_argument("--resolutions", type=Path, help="completed PRIVATE conflict packet from an earlier run")
    parser.add_argument("--interactive", action="store_true", help="resolve <=512 original HUMAN field conflicts in this terminal")
    args = parser.parse_args()
    try:
        require(not (args.resolutions and args.interactive),
            "choose either --resolutions or --interactive")
        require(2 <= len(args.plans) <= 8, "select 2–8 original PRIVATE HUMAN plans")
        require(len({str(p.absolute()) for p in args.plans}) == len(args.plans),
            "do not reuse the same review file")
        admitted = []
        fingerprints = []
        for path in args.plans:
            raw, obj = read_private(path)
            admitted.append(admit_plan(obj))
            fingerprints.append(hashlib.sha256(raw).hexdigest())
        require(len(set(fingerprints)) == len(fingerprints),
            "identical reviewer plans do not establish independent submissions")
        merged, conflicts, contributed = reconcile(admitted)
        sources, n, _ = admitted[0]
        decisions = {}
        if args.resolutions is not None:
            _raw, provided = read_private(args.resolutions)
            decisions = admit_resolutions(provided, sources, n, fingerprints, conflicts)
        elif args.interactive and conflicts:
            decisions = interactive_decisions(conflicts)
        for item in conflicts:
            if decisions:
                merged[item["ordinal"] - 1][item["field"]] = decisions[(
                    item["ordinal"], item["field"])]
        packet = {"kind": "lightup.private_lab_human_conflicts", "version": 1,
            "input_sha256": fingerprints, "source_sha256": sources,
            "ordered_row_count": n, "resolutions": [
                {**item, "value": decisions.get((item["ordinal"], item["field"]))}
                for item in conflicts]}
        counts = {"kind": "lightup.anonymous_lab_human_reconciliation_counts",
            "version": 1, "disposition": "REVIEW_ONLY_DRAFT_HOLD",
            "source_file_count": len(sources), "reviewer_packet_count": len(admitted),
            "row_count": n, "nondefault_submitted_field_slots": contributed,
            "conflicting_field_slots": len(conflicts),
            "source_bound_human_plan_emitted": not conflicts or len(decisions) == len(conflicts),
            "interpretation": "Unsigned HUMAN choices, no reviewer identity, permission, scan, validated finding or actual repair. Small counts may be private."}
        outputs = {
            "anonymous-counts.json": json_bytes(counts),
            "private-resolutions.json": json_bytes(packet),
            "private-conflicts.html": make_review_html(conflicts, len(sources), n),
            "private-resolver.html": make_browser_resolver(),
        }
        if not conflicts or len(decisions) == len(conflicts):
            sparse = [{"ordinal": i + 1, **entry} for i, entry in enumerate(merged)
                if any(entry[k] != DEFAULT[k] for k in ENUMS)]
            original = {"kind": PLAN_KIND, "version": 1,
                "disposition": "REVIEW_ONLY_DRAFT_HOLD",
                **{k: False for k in FALSE_FLAGS},
                "source_sha256": sources, "ordered_row_count": n, "row_plans": sparse,
                "interpretation": "Unsigned multi-packet local HUMAN routing suggestion only; source-byte hashes are not authorizations, signatures, reviewer identities, findings or remediation."}
            outputs["private-merged-original-plan.json"] = json_bytes(original)
        os.mkdir(args.output, mode=0o700)
        try:
            require(stat.S_IMODE(args.output.stat().st_mode) == 0o700,
                "review output directory must be mode 0700")
            for name, body in outputs.items():
                write_new(args.output, name, body)
            dirfd = os.open(args.output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except BaseException:
            for name in outputs:
                (args.output / name).unlink(missing_ok=True)
            args.output.rmdir()
            raise
        print("PRIVATE HUMAN review saved:", args.output,
            "| conflicts:", len(conflicts),
            "| merged original plan:", "yes" if "private-merged-original-plan.json" in outputs else "HOLD")
        return 2 if "private-merged-original-plan.json" in outputs else 3
    except (Hold, OSError) as error:
        print("HOLD:", error, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
