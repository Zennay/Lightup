"""Offline HUMAN-only disclosure follow-up for PRIVATE preflight receipts.

No raw lab input, network, grant, execution, source-authenticity or release.
The SHA-256 here binds HUMAN rows only to receipt bytes, never original sources.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
from pathlib import Path
import stat
import sys

from preflight import Hold, KINDS, require

FIELDS = ("receipt_sha256", "ordinal", "source_kind", "stage", "question", "next_action")
STAGES = ("unreviewed", "privacy_hold", "source_owner_hold", "consent_hold",
          "follow_up_required", "human_reviewed_no_release")
MAX_TEXT = 1200
MAX_BYTES = 256 * 1024
TEMPLATE = "PRIVATE-human-template.csv"
REPORT = "PRIVATE-human-followup.html"
SUMMARY = "PRIVATE-human-summary.csv"
VAULT = "PRIVATE-human-reviewed.luhd"
BUNDLE = "PRIVATE-human-handoff.luhb"
REKEYED_BUNDLE = "PRIVATE-human-handoff-rekeyed.luhb"
RECONCILE_OUTPUTS = ("PRIVATE-reconcile-decisions.csv", "PRIVATE-reconcile-comparison.html",
                     "PRIVATE-reconciled-human.csv", "PRIVATE-reconciled-report.html",
                     "PRIVATE-reconciled-counts.csv", "PRIVATE-reconciled-human.luhb",
                     "PRIVATE-reconcile-interactive-decisions.csv")


def source_bytes(name: str) -> bytes:
    """Read one exact user-owned PRIVATE regular file, never an alias or pipe.

    Input is still unsigned; UID/mode/inode checks provide local custody,
    not genuine source identity, client/operator consent or release authority.
    """
    fd = -1
    try:
        listed = os.stat(name, follow_symlinks=False)
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and 0 < opened.st_size <= MAX_BYTES
                and opened.st_uid == os.getuid()
                and opened.st_mode & 0o077 == 0
                and opened.st_nlink == 1)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns
        )
        require(identity(listed) == identity(opened))
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_BYTES + 1)
            after_read = os.fstat(stream.fileno())
        require(0 < len(raw) <= MAX_BYTES
                and identity(opened) == identity(after_read)
                and identity(opened) == identity(os.stat(name, follow_symlinks=False)))
        return raw
    except OSError:
        raise Hold("HOLD: PRIVATE receipt or answer file not admitted") from None
    finally:
        if fd >= 0:
            os.close(fd)


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    output = {}
    for key, value in pairs:
        require(type(key) is str and key not in output)
        output[key] = value
    return output


def receipt_content(raw: bytes) -> tuple[str, list[dict]]:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold()))
    except (UnicodeError, ValueError, RecursionError, MemoryError):
        raise Hold("HOLD: PRIVATE receipt JSON rejected") from None
    require(type(doc) is dict and doc.get("schema") == "lightup.assessment_disclosure_preflight.v1")
    require(doc.get("status") == "REVIEW_ONLY" and doc.get("source_byte_bound") is False)
    flags = ("source_authenticated", "ground_truth_verified", "client_consent_verified",
             "operator_consent_verified", "authorization_granted", "dispatch_allowed", "release_allowed")
    require(all(doc.get(flag) is False for flag in flags))
    rows = doc.get("inspected_declarations_only")
    require(type(rows) is list and 1 <= len(rows) <= 12 and type(doc.get("source_count")) is int
            and len(rows) == doc["source_count"])
    for n, row in enumerate(rows, 1):
        require(type(row) is dict and type(row.get("ordinal")) is int and row["ordinal"] == n)
        require(type(row.get("kind")) is str and row["kind"] in KINDS)
    return hashlib.sha256(raw).hexdigest(), rows


def receipt(name: str) -> tuple[str, list[dict]]:
    return receipt_content(source_bytes(name))


def safe_note(text: object) -> str:
    require(type(text) is str and len(text) <= MAX_TEXT)
    require(all(char >= " " and char != "\x7f" for char in text))
    # Spreadsheet software may evaluate formulas even when CSV cells are quoted.
    require(not text.lstrip().startswith(("=", "+", "-", "@")))
    return text


def template(digest: str, rows: list[dict]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(FIELDS)
    for row in rows:
        writer.writerow((digest, row["ordinal"], row["kind"], "unreviewed", "", ""))
    return output.getvalue()


def admitted_answers(data: bytes, digest: str, originals: list[dict]) -> list[dict]:
    try:
        value = data.decode("utf-8-sig")
        stream = io.StringIO(value, newline="")
        reader = csv.DictReader(stream, strict=True)
        require(tuple(reader.fieldnames or ()) == FIELDS)
        answers = list(reader)
    except (UnicodeError, csv.Error, ValueError):
        raise Hold("HOLD: HUMAN CSV rejected") from None
    require(len(answers) == len(originals))
    output = []
    for i, (entry, original) in enumerate(zip(answers, originals), 1):
        require(type(entry) is dict and set(entry) == set(FIELDS))
        require(entry["receipt_sha256"] == digest and entry["ordinal"] == str(i))
        require(entry["source_kind"] == original["kind"])
        require(entry["stage"] in STAGES)
        output.append({
            "ordinal": i,
            "kind": original["kind"],
            "stage": entry["stage"],
            "question": safe_note(entry["question"]),
            "next_action": safe_note(entry["next_action"]),
        })
    return output


def render(answers: list[dict]) -> str:
    table = []
    for row in answers:
        cells = (row["ordinal"], row["kind"], row["stage"], row["question"], row["next_action"])
        table.append("<tr>" + "".join("<td>" + html.escape(str(cell)) + "</td>" for cell in cells) + "</tr>")
    counts = {stage: sum(row["stage"] == stage for row in answers) for stage in STAGES}
    counts_line = "; ".join(stage.replace("_", " ") + ": " + str(number)
                            for stage, number in counts.items())
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN disclosure follow-up</title><style>
body{font:16px/1.5 system-ui;max-width:1080px;margin:2rem auto;padding:1rem}
.warning{padding:1rem;border:2px solid #943}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #999;text-align:left;vertical-align:top;padding:.6rem;overflow-wrap:anywhere}
thead{background:#eee}@media print{body{margin:0}}</style></head><body>
<h1>PRIVATE HUMAN disclosure follow-up</h1>
<p class="warning"><strong>NOT RELEASE AUTHORITY.</strong> These are unsigned local
HUMAN notes bound only to an earlier unsigned PRIVATE receipt's exact bytes,
NOT to original assessment artifacts, authenticated reviewers or client grants.
All statuses are human-only; even human_reviewed_no_release is never approval.
Questions and actions can contain confidential information. Keep PRIVATE.
No scanner, model, network, deletion, share or automated release takes place.</p>
<p>Stages: """ + html.escape(counts_line) + """</p>
<table><thead><tr><th>Ordinal</th><th>Kind</th><th>HUMAN stage</th>
<th>HUMAN question</th><th>HUMAN next action</th></tr></thead><tbody>""" + "".join(table) + """</tbody></table>
<p>Obtain original source-owner and independent security/privacy review, authentic
current separate client/operator consent, action-time revocation and explicit HUMAN GO
outside this file. Original #177/#182/#829 and mandatory hosted/named VPS CI remain.</p>
</body></html>"""


def human_counts(answers: list[dict], minimum: int) -> str:
    """Source- and note-free, deliberately small-cohort-suppressed HUMAN counts."""
    require(type(minimum) is int and 5 <= minimum <= 12)
    require(type(answers) is list and 1 <= len(answers) <= 12)
    totals = {stage: sum(item["stage"] == stage for item in answers) for stage in STAGES}
    show_source_count = len(answers) >= minimum
    show_breakdown = show_source_count and all(
        n == 0 or n >= minimum for n in totals.values())
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("field", "value"))
    writer.writerow(("status", "REVIEW_ONLY"))
    writer.writerow(("original_source_authenticated", "FALSE"))
    writer.writerow(("current_consent_verified", "FALSE"))
    writer.writerow(("release_allowed", "FALSE"))
    writer.writerow(("not_anonymity_guarantee", "TRUE"))
    writer.writerow(("HUMAN_receipt_identity", "UNSIGNED_BYTES_ONLY"))
    writer.writerow(("source_count", len(answers) if show_source_count else "SUPPRESSED_SMALL_COHORT"))
    writer.writerow(("human_stages", "DECLARED_NON_AUTHORITATIVE"))
    if show_breakdown:
        for stage in STAGES:
            writer.writerow(("HUMAN_" + stage, totals[stage]))
    else:
        writer.writerow(("HUMAN_stage_breakdown", "SUPPRESSED_SMALL_GROUP"))
    return stream.getvalue()


def publish(output_dir: str, filename: str, content: str | bytes) -> None:
    """Exclusive PRIVATE publish entirely inside one previously opened safe dirfd.

    Refuses a directory symlink, wrong owner/mode, existing final name or
    incomplete publication. Stage and final are on the same directory inode.
    """
    dirfd = -1
    stage = None
    created = False
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        dirfd = os.open(output_dir, flags)
        info = os.fstat(dirfd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0)
        require(filename in (TEMPLATE, REPORT, SUMMARY, VAULT, BUNDLE, REKEYED_BUNDLE) + RECONCILE_OUTPUTS)
        stage = ".lightup-human-private-" + os.urandom(16).hex()
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dirfd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content if type(content) is bytes else content.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(stage, filename, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                follow_symlinks=False)
        created = True
        os.fsync(dirfd)
    except (OSError, ValueError, TypeError):
        if created and dirfd >= 0:
            try:
                os.unlink(filename, dir_fd=dirfd)
            except OSError:
                pass
        raise Hold("HOLD: exclusive PRIVATE output rejected") from None
    finally:
        if stage is not None and dirfd >= 0:
            try:
                os.unlink(stage, dir_fd=dirfd)
            except OSError:
                pass
        if dirfd >= 0:
            os.close(dirfd)



def publish_many(output_dir: str, artifacts: list[tuple[str, str | bytes]]) -> None:
    """Publish a complete PRIVATE HUMAN handoff or leave no new final names.

    All complete files are staged and fsynced before any name becomes visible.
    A failed exclusive link rolls back earlier links inside the *same* pinned
    0700 directory descriptor. A power failure may still interrupt publication;
    this is not a multi-file filesystem transaction or a release gate.
    """
    require(type(artifacts) in (list, tuple) and 1 <= len(artifacts) <= 3)
    allowed = (TEMPLATE, REPORT, SUMMARY, VAULT, BUNDLE,
               REKEYED_BUNDLE) + RECONCILE_OUTPUTS
    names = [name for name, _ in artifacts]
    require(len(set(names)) == len(names) and all(name in allowed for name in names))
    require(all(type(data) in (str, bytes) for _, data in artifacts))
    dirfd = -1
    staged: list[str] = []
    created: list[str] = []
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        dirfd = os.open(output_dir, flags)
        info = os.fstat(dirfd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0)
        for _, content in artifacts:
            stage = ".lightup-human-batch-" + os.urandom(16).hex()
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dirfd)
            staged.append(stage)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content if type(content) is bytes else content.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        for (name, _), stage in zip(artifacts, staged):
            os.link(stage, name, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                    follow_symlinks=False)
            created.append(name)
        os.fsync(dirfd)
    except (OSError, ValueError, TypeError, Hold):
        for name in reversed(created):
            if dirfd >= 0:
                try:
                    os.unlink(name, dir_fd=dirfd)
                except OSError:
                    pass
        raise Hold("HOLD: complete PRIVATE HUMAN handoff was not published") from None
    finally:
        if dirfd >= 0:
            for stage in staged:
                try:
                    os.unlink(stage, dir_fd=dirfd)
                except OSError:
                    pass
            os.close(dirfd)



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PRIVATE source-free HUMAN follow-up, never authority")
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "render", "summarize", "seal", "seal-bundle", "rekey-bundle"):
        sub = commands.add_parser(name)
        sub.add_argument("--receipt", required=name in ("prepare", "seal", "seal-bundle"),
                         help="unsigned PRIVATE preflight receipt (not needed for --bundle)")
        sub.add_argument("--private-output-dir", required=True, help="existing owner-only 0700 directory")
        if name in ("seal", "seal-bundle"):
            sub.add_argument("--answers", required=True, help="source-free admitted PRIVATE HUMAN CSV")
        elif name == "rekey-bundle":
            sub.add_argument("--bundle", required=True, help="original encrypted PRIVATE HUMAN handoff")
        elif name != "prepare":
            inputs = sub.add_mutually_exclusive_group(required=True)
            inputs.add_argument("--answers", help="plaintext PRIVATE HUMAN CSV")
            inputs.add_argument("--vault", help="sealed PRIVATE HUMAN .luhd (separate receipt)")
            inputs.add_argument("--bundle", help="encrypted PRIVATE receipt+HUMAN .luhb, password only")
        if name == "summarize":
            sub.add_argument("--minimum-cohort", type=int, default=5,
                             help="HUMAN stage privacy floor, 5-12")
    args = parser.parse_args(argv)
    try:
        source = None
        raw_receipt = None
        if args.action in ("render", "summarize", "rekey-bundle") and args.bundle:
            require(args.receipt is None)
            try:
                from vault_native import VaultHold, decrypt_bundle
                raw_receipt, source = decrypt_bundle(args.bundle)
            except (ImportError, VaultHold):
                raise Hold("HOLD: complete encrypted HUMAN package refused") from None
            digest, rows = receipt_content(raw_receipt)
        else:
            require(args.receipt is not None)
            raw_receipt = source_bytes(args.receipt)
            digest, rows = receipt_content(raw_receipt)
        if args.action == "prepare":
            publish(args.private_output_dir, TEMPLATE, template(digest, rows))
        elif args.action == "rekey-bundle":
            admitted_answers(source, digest, rows)
            try:
                from vault_native import VaultHold, encrypt_bundle
                sealed = encrypt_bundle(raw_receipt, source)
            except (ImportError, VaultHold):
                raise Hold("HOLD: encrypted HUMAN rekey refused") from None
            publish(args.private_output_dir, REKEYED_BUNDLE, sealed)
        elif args.action in ("seal", "seal-bundle"):
            source = source_bytes(args.answers)
            admitted_answers(source, digest, rows)
            try:
                from vault_native import VaultHold, encrypt_vault, encrypt_bundle
                sealed = (encrypt_bundle(raw_receipt, source) if args.action == "seal-bundle"
                          else encrypt_vault(source, digest))
            except (ImportError, VaultHold):
                raise Hold("HOLD: encrypted HUMAN export refused") from None
            publish(args.private_output_dir, BUNDLE if args.action == "seal-bundle" else VAULT, sealed)
        else:
            if source is None:
                if args.vault:
                    try:
                        from vault_native import VaultHold, decrypt_vault
                        source = decrypt_vault(args.vault, digest)
                    except (ImportError, VaultHold):
                        raise Hold("HOLD: encrypted HUMAN vault refused") from None
                else:
                    source = source_bytes(args.answers)
            answers = admitted_answers(source, digest, rows)
            if args.action == "summarize":
                publish(args.private_output_dir, SUMMARY,
                        human_counts(answers, args.minimum_cohort))
            else:
                publish(args.private_output_dir, REPORT, render(answers))
    except Hold:
        print("HOLD: PRIVATE HUMAN workflow refused; no permission or release", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: new PRIVATE HUMAN output created; no assessment authority")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
