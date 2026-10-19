"""Original-authenticated encrypted finding intake, priority and revision briefs.

Offline HUMAN discussion only. No grant, consent, target calls or security verdict.
"""
from __future__ import annotations
import argparse
import csv
import io
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "remediation-secure-export"))
from secure_export import (AccountLockedError, COLUMNS, FALSE, SEVERITIES, STATES,
                           _authorized_summary, _literal, _strict_summary,
                           _unique_pairs, _vault)

KIND = "lightup.private_authenticated_engagement_brief"
FIELDS = {"kind", "version", "disposition", "client", "engagement",
          "source_sha256", "source_count", "source_csv", "authority"}
MAX_PACKET = 1300000
ORDER = ("critical", "high", "medium", "low", "info")
CHANGE_FIELDS = ("title", "severity", "retest_status", "remediation")


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def rows(source):
    reader = csv.DictReader(io.StringIO(source, newline=""), strict=True)
    if reader.fieldnames != list(COLUMNS):
        raise ValueError("Bad original source headers")
    result = []
    for row in reader:
        if set(row) != set(COLUMNS) or any(type(row.get(k)) is not str for k in COLUMNS):
            raise ValueError("Bad original source row")
        result.append({k: row[k] for k in COLUMNS})
    if not 1 <= len(result) <= 350:
        raise ValueError("Bad source membership")
    return result


def create_packet(source, client, engagement):
    digest, count = _strict_summary(source)
    if count != len(rows(source)):
        raise ValueError("Original source count changed")
    packet = dict(kind=KIND, version=1, disposition="PRIVATE_HUMAN_SOURCE_DRAFT",
                  client=_literal(client, "client"), engagement=_literal(engagement, "engagement"),
                  source_sha256=digest, source_count=count, source_csv=source,
                  authority={k: False for k in FALSE})
    raw = canonical(packet)
    if len(raw) > MAX_PACKET:
        raise ValueError("Oversized PRIVATE source")
    return raw


def decode_packet(raw):
    if not raw or len(raw) > MAX_PACKET:
        raise ValueError("Bad PRIVATE source length")
    packet = json.loads(raw.decode("ascii", "strict"), object_pairs_hook=_unique_pairs)
    if type(packet) is not dict or set(packet) != FIELDS or canonical(packet) != raw:
        raise ValueError("Unknown PRIVATE source")
    if (packet["kind"] != KIND or type(packet["version"]) is not int
            or packet["version"] != 1 or packet["disposition"] != "PRIVATE_HUMAN_SOURCE_DRAFT"
            or type(packet["authority"]) is not dict
            or set(packet["authority"]) != set(FALSE)
            or any(packet["authority"][k] is not False for k in FALSE)):
        raise ValueError("PRIVATE source asserted authority")
    _literal(packet["client"], "client")
    _literal(packet["engagement"], "engagement")
    if type(packet["source_csv"]) is not str:
        raise ValueError("Bad source")
    digest, count = _strict_summary(packet["source_csv"])
    if (type(packet["source_sha256"]) is not str
            or digest != packet["source_sha256"]
            or type(packet["source_count"]) is not int
            or count != packet["source_count"]):
        raise ValueError("PRIVATE source integrity HOLD")
    return packet, rows(packet["source_csv"])


def read_encrypted(path):
    vault = _vault()
    cipher = vault._private_input(path.expanduser().absolute(), vault.MAX_VAULT)
    secret = vault._password("PRIVATE engagement vault passphrase: ", fresh=False)
    raw, content_type, _ = vault._open(cipher, secret)
    if content_type != "application/json":
        raise ValueError("Unexpected encrypted content type")
    return decode_packet(raw)


def source_auth(args):
    return _authorized_summary(db=args.db, email=args.email, client_id=args.client_id,
                               engagement_id=args.engagement_id)


def counts(records):
    severity = {x: 0 for x in SEVERITIES}
    retest = {x: 0 for x in STATES}
    for r in records:
        severity[r["severity"]] += 1
        retest[r["retest_status"]] += 1
    return severity, retest


def escape(value):
    if type(value) is not str:
        raise ValueError("Bad original text")
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for char in ("\\", "*", "_", "{", "}", "[", "]", "(", ")",
                 "#", "+", "-", ".", "!", "|", "~"):
        value = value.replace(char, "\\" + char)
    return value.replace("\n", " ").replace("\r", " ")


def brief(records):
    sev, stat = counts(records)
    lines = ["# PRIVATE HUMAN engagement action brief", "",
             "Original source labels are not verified security findings or fixes.",
             "This is NOT a grant, client/operator consent, permission for scanning, "
             "execution, remediation or retest.", "", "## Original source totals", "",
             "- Original source rows: " + str(len(records))]
    for name in ORDER:
        lines.append("- Source severity " + name + ": " + str(sev[name]))
    for name in STATES:
        lines.append("- Source retest label " + name + ": " + str(stat[name]))
    lines += ["", "## Human follow-up queue", "",
              "All original finding text is untrusted. Owner, action and verification "
              "must be reviewed separately.", ""]
    ordered = sorted(records, key=lambda r: (ORDER.index(r["severity"]),
                                             r["retest_status"] == "fixed", r["finding_id"]))
    for idx, r in enumerate(ordered, 1):
        lines += ["### " + str(idx) + ". " + escape(r["finding_id"]), "",
                  "- Source severity: " + escape(r["severity"]),
                  "- Original title: " + escape(r["title"]),
                  "- Original retest label (unverified): " + escape(r["retest_status"]),
                  "- Original suggested remediation: " + escape(r["remediation"]),
                  "- HUMAN owner: unassigned",
                  "- HUMAN next action: separate review required",
                  "- Verified retest: unknown", ""]
    return "\n".join(lines).rstrip() + "\n"


def compare(previous, current):
    a = {r["finding_id"]: r for r in previous}
    b = {r["finding_id"]: r for r in current}
    changed = {k: [f for f in CHANGE_FIELDS if a[k][f] != b[k][f]]
               for k in a.keys() & b.keys() if a[k] != b[k]}
    return sorted(b.keys() - a.keys()), sorted(a.keys() - b.keys()), changed, a, b


def revision_brief(previous, current):
    added, absent, changed, old, new = compare(previous, current)
    lines = ["# PRIVATE HUMAN original finding source revision", "",
             "Original source differences are not proof of a fix or verified retest.",
             "Original absent or fixed labels never authorize closure or execution.", "",
             "- Previous rows: " + str(len(previous)),
             "- Current freshly authenticated rows: " + str(len(current)),
             "- New original IDs: " + str(len(added)),
             "- Absent original IDs (HOLD): " + str(len(absent)),
             "- Changed original records: " + str(len(changed)), "",
             "## Newly present original IDs", ""]
    lines += ["- " + escape(i) for i in added] or ["- None"]
    lines += ["", "## Absent original IDs (not fixed)", ""]
    lines += ["- " + escape(i) for i in absent] or ["- None"]
    lines += ["", "## Changed original records", ""]
    if not changed:
        lines.append("- None")
    for ident in sorted(changed):
        lines.append("- " + escape(ident) + ": " + ", ".join(changed[ident]))
        for field in changed[ident]:
            lines.append("  - Earlier " + field + ": " + escape(old[ident][field]))
            lines.append("  - Current " + field + ": " + escape(new[ident][field]))
    return "\n".join(lines).rstrip() + "\n"


def save_markdown(args, text):
    """Emit owner-private literal .md or encrypted .ltv without plaintext disk."""
    if bool(args.output) == bool(args.sealed_markdown) or not args.ack_private_markdown:
        raise ValueError("Choose exactly one explicitly acknowledged PRIVATE handoff")
    raw = text.encode("utf-8", "strict")
    if not raw or len(raw) > 4 * 1024 * 1024:
        raise ValueError("Invalid PRIVATE handoff size")
    path = (args.output if args.output is not None else args.sealed_markdown).expanduser().absolute()
    other = getattr(args, "capture_current", None)
    if path == args.input.expanduser().absolute() or (
        other is not None and path == other.expanduser().absolute()
    ):
        raise ValueError("Original source and new outputs must be distinct")
    vault = _vault()
    if args.sealed_markdown is not None:
        if path.suffix.lower() != ".ltv":
            raise ValueError("Encrypted HUMAN handoff requires .ltv")
        password = vault._password("New PRIVATE human handoff passphrase: ", fresh=True)
        vault._exclusive_output(path, vault._seal(vault._inner(raw, "text/markdown"), password))
    else:
        if path.suffix.lower() != ".md":
            raise ValueError("PRIVATE plaintext human handoff requires .md")
        vault._exclusive_output(path, raw)


def capture_current_revision(args, source):
    """Keep old encrypted history and independently encrypt the new original source."""
    output = args.capture_current.expanduser().absolute()
    if output.suffix.lower() != ".ltv" or output == args.input.expanduser().absolute():
        raise ValueError("New .ltv revision must not replace original")
    if any(v is not None and output == v.expanduser().absolute()
           for v in (args.output, args.sealed_markdown)):
        raise ValueError("New revision and HUMAN handoff paths must differ")
    payload = create_packet(source, args.client_id, args.engagement_id)
    vault = _vault()
    password = vault._password("New PRIVATE revision passphrase: ", fresh=True)
    vault._exclusive_output(output, vault._seal(vault._inner(payload, "application/json"), password))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    cmd = ap.add_subparsers(dest="command", required=True)
    capture = cmd.add_parser("capture", help="Current original login -> encrypted .ltv only")
    inspect = cmd.add_parser("inspect", help="ID-free historical source aggregates, no current authority")
    review = cmd.add_parser("review-current", help="Fresh original account login + revision review")
    open_now = cmd.add_parser("open-current", help="Exact current original source -> private HUMAN brief")
    for action in (capture, review, open_now):
        for key in ("db", "email", "client-id", "engagement-id"):
            action.add_argument("--" + key, required=True)
    capture.add_argument("--output", required=True, type=Path)
    for action in (inspect, review, open_now):
        action.add_argument("--input", required=True, type=Path)
    for action in (review, open_now):
        action.add_argument("--output", type=Path, help="New owner-private 0600 HUMAN .md")
        action.add_argument("--sealed-markdown", type=Path, help="Encrypted HUMAN .ltv, no plaintext file")
        action.add_argument("--ack-private-markdown", action="store_true")
    review.add_argument("--capture-current", type=Path, help="Fresh authorized source into NEW encrypted revision .ltv")
    args = ap.parse_args(argv)
    try:
        vault = _vault()
        if args.command == "capture":
            if args.output.suffix.lower() != ".ltv":
                raise ValueError("Encrypted snapshot must use .ltv")
            source = source_auth(args)
            raw = create_packet(source, args.client_id, args.engagement_id)
            password = vault._password("New PRIVATE engagement passphrase: ", fresh=True)
            vault._exclusive_output(args.output.expanduser().absolute(),
                                    vault._seal(vault._inner(raw, "application/json"), password))
            print("Encrypted source captured directly from original authenticated selector; no plaintext disk.")
            print("Historical source is not consent, security verdict or grant.")
            return 0
        if args.input.suffix.lower() != ".ltv":
            raise ValueError("Encrypted input must be original .ltv")
        # Current-source commands first authenticate independently before decrypting.
        current_source = source_auth(args) if args.command != "inspect" else None
        packet, old = read_encrypted(args.input)
        if args.command == "inspect":
            severity, statuses = counts(old)
            print("Historical PRIVATE source, no current access or verified outcome:", len(old), "rows")
            for name in ORDER:
                print("Source", name, severity[name])
            for name in STATES:
                print("Source retest", name, statuses[name])
            return 0
        if packet["client"] != args.client_id or packet["engagement"] != args.engagement_id:
            raise ValueError("Engagement identity mismatch")
        digest, count = _strict_summary(current_source)
        now = rows(current_source)
        if len(now) != count:
            raise ValueError("Current source count mismatch")
        if args.command == "open-current":
            if digest != packet["source_sha256"] or count != packet["source_count"]:
                raise ValueError("Source drift: use review-current instead")
            save_markdown(args, brief(now))
            print("PRIVATE HUMAN action handoff created from exact freshly authenticated source.")
            return 0
        added, absent, changed, _, _ = compare(old, now)
        print("Original-source changes: added", len(added), "absent", len(absent),
              "changed", len(changed), "unchanged", count-len(added)-len(changed))
        print("Exact original snapshot:", digest == packet["source_sha256"])
        if args.output is not None or args.sealed_markdown is not None:
            save_markdown(args, revision_brief(old, now))
            print("PRIVATE HUMAN revision handoff created, not verified remediation.")
        if args.capture_current is not None:
            capture_current_revision(args, current_source)
            print("New original-source revision encrypted independently; original history retained.")
        return 0
    except (AccountLockedError, PermissionError, ValueError, KeyError, OSError,
            UnicodeError, sqlite3.DatabaseError, EOFError, KeyboardInterrupt,
            csv.Error, TypeError):
        print("HOLD: source not admitted; review original access and private storage.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
