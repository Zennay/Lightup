#!/usr/bin/env python3
"""Private, operator-initiated original LightUp request-binding snapshot collection.

DRAFT/HOLD. Only delegates an explicitly interactive single-proposal read/export
to the genuine source-owner-bound PR #1590 CLI. Never grants, scans or authorizes.
Stdlib only; does not import credentials, duplicate authorization logic, or talk
to a target. Requires the separately reviewed CLI to be installed/composed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone

FORMAT = "lightup.request_binding_capture_ledger.v1"
SOURCE_FORMAT = "lightup.request_binding_preparation.v1"
FALSE_KEYS = (
    "client_consent_verified", "operator_consent_verified", "authorization_granted",
    "execution_allowed", "release_approved",
)
AUTHORITY = {key: False for key in FALSE_KEYS}
NAME_RE = re.compile(r"^original-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\.json$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 12, 2_000_000, 12_000_000
LEDGER = "capture-ledger.private.json"
HOLD_MESSAGE = "HOLD: private original-source integrity or operator requirements were not satisfied."


class Hold(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("duplicate JSON property")
        result[key] = value
    return result


def read_bytes(path: Path, cap: int, *, private: bool = True) -> bytes:
    if path.is_symlink():
        raise Hold("symlinked private source refused")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                or (private and stat.S_IMODE(s.st_mode) & 0o077) or not 0 < s.st_size <= cap):
            raise Hold("source file is not a bounded regular file")
        # Read exactly observed bytes, refuse a concurrent source mutation.
        payload = os.read(fd, cap + 1)
        if len(payload) != s.st_size or os.fstat(fd).st_size != s.st_size:
            raise Hold("source bytes changed while reading")
        return payload
    finally:
        os.close(fd)


def parse_json(raw: bytes) -> dict:
    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicates,
                            parse_constant=lambda _: (_ for _ in ()).throw(Hold("non-finite JSON value")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Hold("invalid private UTF-8 JSON source") from exc
    if type(result) is not dict:
        raise Hold("private JSON root is not an object")
    return result


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def assert_authority(value: object) -> None:
    if type(value) is not dict or set(value) != set(FALSE_KEYS) or any(value[key] is not False for key in FALSE_KEYS):
        raise Hold("source authority flags must be exactly false")


def source_metadata(raw: bytes) -> dict:
    obj = parse_json(raw)
    if obj.get("format") != SOURCE_FORMAT or obj.get("disposition") not in {
        "REVIEW_ONLY_SINGLE_CANDIDATE", "HOLD_NO_CANDIDATE", "HOLD_AMBIGUOUS_CANDIDATES"
    }:
        raise Hold("original exporter must produce a single-selection REVIEW_ONLY v1 report")
    assert_authority(obj.get("authority"))
    source, summary, candidates = obj.get("source"), obj.get("summary"), obj.get("candidates")
    if type(source) is not dict or source.get("source_owner_ref") != "PR-1570":
        raise Hold("original owner reference missing")
    if type(summary) is not dict or type(candidates) is not list or len(candidates) > 500:
        raise Hold("original source summary malformed")
    if summary.get("recorded_requests") != len(candidates):
        raise Hold("source request count contradicts candidate rows")
    selection, revision = source.get("request_selection_digest_unsigned"), source.get("source_revision_sha256_unsigned")
    if any(type(value) is not str or DIGEST_RE.fullmatch(value) is None for value in (selection, revision)):
        raise Hold("original source/selection digest missing or malformed")
    date = source.get("review_instant_utc")
    if type(date) is not str or not 20 <= len(date) <= 60:
        raise Hold("original review instant malformed")
    try:
        dt = datetime.fromisoformat(date.replace("Z", "+00:00"))
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise Hold("source review instant must be timezone-aware")
    except ValueError as exc:
        raise Hold("original review timestamp malformed") from exc
    return {"selection": selection, "revision": revision, "review_instant_utc": date}


def private_dir(folder: Path) -> Path:
    if folder.is_symlink():
        raise Hold("private folder must not be a symlink")
    p = folder.resolve(strict=True)
    st = p.stat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) & 0o077):
        raise Hold("private folder must be owned by the current user with 0700 restrictions")
    return p


def fresh_private_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def persist_ledger(folder: Path, ledger: dict) -> None:
    # No backup of sensitive previous bytes: atomic replace within private dir.
    raw = (json.dumps(ledger, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    scratch = folder / (".ledger-write-" + secrets.token_hex(12))
    fresh_private_file(scratch, raw)
    try:
        os.replace(scratch, folder / LEDGER)
        fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if scratch.exists():
            scratch.unlink()


def new_ledger() -> dict:
    return {"format": FORMAT, "authority": dict(AUTHORITY),
            "selection_digest_unsigned": None, "snapshots": []}


def read_ledger(folder: Path, *, require_entries: bool = False) -> tuple[dict, list[bytes]]:
    data = parse_json(read_bytes(folder / LEDGER, 200_000))
    if set(data) != {"format", "authority", "selection_digest_unsigned", "snapshots"} or data["format"] != FORMAT:
        raise Hold("private ledger format mismatch")
    assert_authority(data["authority"])
    entries = data["snapshots"]
    if type(entries) is not list or len(entries) > MAX_FILES or (require_entries and len(entries) < 2):
        raise Hold("private capture ledger has unsuitable number of entries")
    selection = data["selection_digest_unsigned"]
    if (selection is None) != (len(entries) == 0) or (
        selection is not None and (type(selection) is not str or DIGEST_RE.fullmatch(selection) is None)
    ):
        raise Hold("private ledger selection digest mismatch")
    files, seen, total = [], set(), 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"filename", "original_file_sha256", "source_revision_sha256_unsigned", "review_instant_utc"}:
            raise Hold("private snapshot ledger entry malformed")
        name = entry["filename"]
        if type(name) is not str or NAME_RE.fullmatch(name) is None or name in seen:
            raise Hold("private snapshot filename invalid or duplicated")
        seen.add(name)
        raw = read_bytes(folder / name, MAX_FILE_BYTES)
        total += len(raw)
        if total > MAX_TOTAL_BYTES or digest(raw) != entry["original_file_sha256"]:
            raise Hold("private source file byte digest or total budget mismatch")
        meta = source_metadata(raw)
        if (meta["selection"] != selection or meta["revision"] != entry["source_revision_sha256_unsigned"]
                or meta["review_instant_utc"] != entry["review_instant_utc"]):
            raise Hold("original source report and private ledger metadata disagree")
        files.append(raw)
    return data, files


def initialize(folder: Path) -> int:
    os.mkdir(folder, 0o700)
    root = private_dir(folder)
    fresh_private_file(root / LEDGER, (json.dumps(new_ledger(), indent=2) + "\n").encode("ascii"))
    print("REVIEW_ONLY: restricted 0700 operator capture folder initialized; no grants or scans.")
    return 0


def capture(args: argparse.Namespace) -> int:
    root = private_dir(Path(args.dir))
    ledger, old = read_ledger(root)
    if len(old) >= MAX_FILES or sum(len(raw) for raw in old) >= MAX_TOTAL_BYTES:
        raise Hold("maximum original snapshot collection reached; create a new private folder")
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise Hold("original operator password prompt requires an interactive terminal")
    if args.db is None or Path(args.db).is_symlink() or not Path(args.db).is_file():
        raise Hold("provide the existing genuine original LightUp SQLite database")
    if not args.asset or args.risk not in (1, 2, 3, 4):
        raise Hold("capture requires an explicit canonical proposed scope and risk")
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"original-{now}-{secrets.token_hex(8)}.json"
    dest = root / name
    staging = root / (".capture-pending-" + secrets.token_hex(16) + ".json")
    # This is always a wholly NEW file belonging to this capture attempt.
    # On source denial/scope mismatch/size failure it is deleted, so a
    # rejected private capture cannot leave an untracked sensitive source.
    cmd = [
        sys.executable, "-m", "lightup.request_binding_readiness_cli",
        "--db", str(Path(args.db).resolve()), "--email", args.email,
        "--engagement-id", args.engagement_id, "--output", str(staging), "--risk", str(args.risk),
    ]
    if args.client_id:
        cmd.extend(["--client-id", args.client_id])
    for literal in args.asset:
        cmd.extend(["--asset", literal])
    created = False
    try:
        # Original source module (not this helper) enforces authenticated
        # operator lockout, canonical scope checks, persisted source lineage.
        # Password is entered only into its live interactive TTY prompt.
        status = subprocess.run(cmd, check=False).returncode
        if status != 0:
            raise Hold("genuine original operator/source review refused capture")
        raw = read_bytes(staging, MAX_FILE_BYTES)
        meta = source_metadata(raw)
        if (ledger["selection_digest_unsigned"] is not None
                and meta["selection"] != ledger["selection_digest_unsigned"]):
            raise Hold("captured source selection differs from existing restricted ledger")
        if sum(map(len, old)) + len(raw) > MAX_TOTAL_BYTES:
            raise Hold("private original source budget exceeded")
        if any(entry["original_file_sha256"] == digest(raw) for entry in ledger["snapshots"]):
            raise Hold("identical original file bytes already stored")
        # Safe named capture can only be created if no destination already
        # exists: never overwrite an operator's existing original records.
        os.link(staging, dest, follow_symlinks=False)
        created = True
        ledger["selection_digest_unsigned"] = meta["selection"]
        ledger["snapshots"].append({
            "filename": name, "original_file_sha256": digest(raw),
            "source_revision_sha256_unsigned": meta["revision"],
            "review_instant_utc": meta["review_instant_utc"],
        })
        try:
            persist_ledger(root, ledger)
        except BaseException:
            # Remove only this just-created, uncommitted source artifact.
            dest.unlink()
            created = False
            raise
    finally:
        if staging.exists():
            staging.unlink()
    if not created:
        raise Hold("original export was never committed to the private ledger")
    print(f"REVIEW_ONLY: recorded original authenticated-source export as PRIVATE {name}.")
    print(f"Snapshots: {len(ledger['snapshots'])}/{MAX_FILES}. Open the offline history desk and select these original JSON files together.")
    return 0


def list_snapshots(folder: Path) -> int:
    ledger, _ = read_ledger(private_dir(folder))
    print(f"REVIEW_ONLY · {len(ledger['snapshots'])} private original reports · untrusted unsigned source history")
    for i, entry in enumerate(ledger["snapshots"], 1):
        print(f"{i:02d}. {entry['filename']} · original UTC {entry['review_instant_utc']} · source digest {entry['source_revision_sha256_unsigned'][:10]}…")
    print("All grant/consent/scan/release authority remains FALSE. File order is not verified chronology.")
    return 0


def bundle(folder: Path, outfile: Path, template: Path, explicit_private: bool) -> int:
    if not explicit_private:
        raise Hold("PRIVATE bundle embeds original stored request data; explicitly supply --include-private-source-data")
    root = private_dir(folder)
    ledger, originals = read_ledger(root, require_entries=True)
    if len(originals) > MAX_FILES:
        raise Hold("private bundled original report count exceeded")
    if (outfile.suffix.lower() != ".html" or outfile.is_symlink() or outfile.exists()
            or outfile.parent.resolve(strict=True) != root):
        raise Hold("PRIVATE bundle must be a NEW file inside its original restricted capture directory")
    template_bytes = read_bytes(template, 200_000, private=False)
    try:
        html = template_bytes.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise Hold("original offline app template is not valid UTF-8") from exc
    # Original PRIVATE sources must never be inserted into a script-modified
    # template. Do not allow custom template URLs/paths from the operator.
    for tag in ("style", "script"):
        start, end = f"<{tag}>", f"</{tag}>"
        if html.count(start) != 1 or html.count(end) != 1:
            raise Hold("operator app inline CSP source structure changed")
        inline = html.split(start, 1)[1].split(end, 1)[0]
        pin = base64.b64encode(hashlib.sha256(inline.encode("utf-8")).digest()).decode("ascii")
        if f"{tag}-src 'sha256-{pin}'" not in html:
            raise Hold("operator app exact inline CSP fingerprint mismatch")
    for directive in ("default-src 'none'", "connect-src 'none'",
                      "form-action 'none'", "object-src 'none'"):
        if directive not in html:
            raise Hold("private operator bundle requires strict offline CSP")
    marker = '<template id="lightup-private-bundle"></template>'
    if html.count(marker) != 1:
        raise Hold("expected original private bundle slot absent from offline app")
    encoded = ".".join(base64.b64encode(raw).decode("ascii") for raw in originals)
    # Base64 alphabet cannot introduce markup. Script and stylesheet bytes
    # stay exactly SHA256-CSP pinned; only inert template TEXT changes.
    html = html.replace(marker, f'<template id="lightup-private-bundle">{encoded}</template>')
    output = html.encode("utf-8")
    if len(output) > 20_000_000:
        raise Hold("private one-file workbench exceeds configured size")
    fresh_private_file(outfile, output)
    print("PRIVATE REVIEW_ONLY: assembled a local 0600 workbench containing original sensitive source JSON.")
    print("Do NOT share/upload this HTML. The copies are unsigned, unauthenticated outside original capture, and NOT consent, grant, scan or release.")
    return 0


def cli() -> int:
    parser = argparse.ArgumentParser(description="LightUp PRIVATE original-request review capture (never grants/scans)")
    sub = parser.add_subparsers(dest="mode", required=True)
    init = sub.add_parser("init", help="create an entirely new restricted 0700 collection")
    init.add_argument("--dir", required=True)
    cap = sub.add_parser("capture", help="authenticate using original PR #1590 CLI and preserve a single private JSON export")
    cap.add_argument("--dir", required=True)
    cap.add_argument("--db", required=True)
    cap.add_argument("--email", required=True)
    cap.add_argument("--engagement-id", required=True)
    cap.add_argument("--client-id")
    cap.add_argument("--asset", action="append", required=True)
    cap.add_argument("--risk", type=int, required=True, choices=(1, 2, 3, 4))
    ls = sub.add_parser("list", help="inspect previously recorded originals without opening their sensitive contents")
    ls.add_argument("--dir", required=True)
    b = sub.add_parser("bundle", help="assemble a standalone offline local HTML with embedded PRIVATE originals")
    b.add_argument("--dir", required=True)
    b.add_argument("--output", required=True)
    b.add_argument("--include-private-source-data", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.mode == "init":
            return initialize(Path(args.dir))
        if args.mode == "capture":
            return capture(args)
        if args.mode == "list":
            return list_snapshots(Path(args.dir))
        if args.mode == "bundle":
            return bundle(Path(args.dir), Path(args.output), Path(__file__).with_name("standalone.html"), args.include_private_source_data)
    except (Hold, OSError, ValueError, UnicodeError) as exc:
        # Never print raw source data, original assets/clients, or credentials.
        print(f"{HOLD_MESSAGE} ({type(exc).__name__})", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
