"""AES-GCM offline custody for source-bound HUMAN timeline briefs.

Consumes original encrypted source/workplans, publishes only encrypted summary
and optional PRIVATE ID detail. Operator must separately confirm transport.
No real-client/owner authentication, security fix, retest or scope permission.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from .private_export_encrypted import _open_sealed, _passphrase, _seal
from .private_export_handoff import _atomic_private_publish, _no_duplicate_keys, _output_path
from .private_export_history import _as_of, _html, _priorities, _read_history, _summarize

KIND = "lightup.private_human_history_vault"
MAGIC = b"LIGHTUP-PRIVATE-HUMAN-HISTORY-V1\x00"
LIMIT = 1024 * 1024
ENC_EXTENSION = ".luh"
REQUIRED = {
    "kind", "version", "generated_utc", "brief_sha256", "html_base64",
    "operator_declared_snapshot_order", "includes_private_actions",
    "source_record_count", "snapshot_count", "latest_attention",
    "authorizes_action", "certifies_remediation",
    "authenticates_recipient_or_client", "encrypted",
}


def _read_vault(filename: str, secret: str) -> tuple[dict, bytes]:
    path = Path(filename).expanduser()
    maximum = len(MAGIC) + 16 + 12 + LIMIT + 16
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("missing or oversized encrypted private timeline")
    raw = _open_sealed(path.read_bytes(), secret, magic=MAGIC, max_plaintext=LIMIT)
    try:
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid decrypted HUMAN timeline metadata") from exc
    if type(data) is not dict or set(data) != REQUIRED:
        raise ValueError("unexpected HUMAN timeline schema")
    if data["kind"] != KIND or type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("unrecognized HUMAN history vault version")
    for field in ("authorizes_action", "certifies_remediation",
                  "authenticates_recipient_or_client"):
        if data[field] is not False:
            raise ValueError("forbidden security authority assertion in HUMAN timeline")
    if data["encrypted"] is not True or data["operator_declared_snapshot_order"] is not True:
        raise ValueError("invalid ciphertext provenance declaration")
    if type(data["includes_private_actions"]) is not bool:
        raise ValueError("invalid private action flag")
    for field in ("source_record_count", "snapshot_count", "latest_attention"):
        if type(data[field]) is not int or not 0 <= data[field] <= 128:
            raise ValueError("invalid bounded HUMAN metrics")
    if not 1 <= data["snapshot_count"] <= 12:
        raise ValueError("invalid HUMAN snapshot count")
    if (type(data["brief_sha256"]) is not str or len(data["brief_sha256"]) != 64 or
            type(data["html_base64"]) is not str or len(data["html_base64"]) > LIMIT * 2):
        raise ValueError("invalid private HTML digest or envelope")
    if type(data["generated_utc"]) is not str or len(data["generated_utc"]) > 48:
        raise ValueError("invalid local creation label")
    try:
        generated = datetime.fromisoformat(data["generated_utc"])
        if generated.utcoffset() is None:
            raise ValueError("missing creation timezone")
    except ValueError as exc:
        raise ValueError("invalid creation instant") from exc
    try:
        html = base64.b64decode(data["html_base64"], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid authenticated private HTML payload") from exc
    if not html or len(html) > LIMIT:
        raise ValueError("invalid private HTML size")
    if hashlib.sha256(html).hexdigest() != data["brief_sha256"]:
        raise ValueError("encrypted private HTML digest mismatch")
    if not html.startswith(b'<!doctype html><html lang="en">'):
        raise ValueError("unrecognized private HTML payload")
    if b'http-equiv="Content-Security-Policy"' not in html:
        raise ValueError("private HTML missing static CSP")
    return data, html


def _save(filename: str, data: dict) -> str:
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("utf-8", "strict")
    if len(serialized) > LIMIT:
        raise ValueError("private history exceeds encrypted size budget")
    secret = _passphrase("New PRIVATE HUMAN history passphrase", confirm=True)
    ciphertext = _seal(serialized, secret, magic=MAGIC, max_plaintext=LIMIT)
    _atomic_private_publish(_output_path(filename, ENC_EXTENSION), ciphertext)
    return hashlib.sha256(ciphertext).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt/private-open original-source HUMAN history, without a plaintext intermediate"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create", help="compile and encrypt exact-source HUMAN history directly")
    create.add_argument("source")
    create.add_argument("plans", nargs="+")
    create.add_argument("--output", required=True)
    create.add_argument("--as-of", help="UTC YYYY-MM-DD for proposed human followup aging")
    create.add_argument("--include-private-actions", action="store_true")
    create.add_argument("--ack-private-attention-ids", action="store_true")
    inspect = sub.add_parser("inspect", help="decrypt and print ID-free counts, no HTML created")
    inspect.add_argument("vault")
    open_action = sub.add_parser("open", help="decrypt into new 0600 PRIVATE HTML file")
    open_action.add_argument("vault")
    open_action.add_argument("--output", required=True)
    open_action.add_argument("--ack-plaintext-html", action="store_true")
    rotate = sub.add_parser("rotate", help="change vault encryption passphrase without writing plaintext")
    rotate.add_argument("vault")
    rotate.add_argument("--output", required=True)
    for action in (create, inspect, open_action, rotate):
        action.add_argument("--ack-private-handling", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_handling:
            raise ValueError("explicit recipient/private handling acknowledgment required")
        if args.action == "create":
            if args.include_private_actions and not args.ack_private_attention_ids:
                raise ValueError("original IDs/owner aliases require explicit private acknowledgment")
            destination = _output_path(args.output, ENC_EXTENSION)
            _manifest, rows, plans = _read_history(args.source, args.plans)
            moment = _as_of(args.as_of)
            summary = _summarize(_manifest, rows, plans, moment)
            queue = _priorities(rows, plans[-1], moment)
            html = _html(summary, queue, args.include_private_actions)
            envelope = {
                "kind": KIND, "version": 1,
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "brief_sha256": hashlib.sha256(html).hexdigest(),
                "html_base64": base64.b64encode(html).decode("ascii"),
                "operator_declared_snapshot_order": True,
                "includes_private_actions": args.include_private_actions,
                "source_record_count": len(rows),
                "snapshot_count": len(plans),
                "latest_attention": summary["latest_attention"]["original_findings_requiring_human_review"],
                "authorizes_action": False, "certifies_remediation": False,
                "authenticates_recipient_or_client": False, "encrypted": True,
            }
            checksum = _save(str(destination), envelope)
            print("Original-source HUMAN history saved as AES-GCM ciphertext without plaintext disk output.")
            print("Signed owner/client identity: NONE · security verdict: NONE")
            print("Unsigned ciphertext SHA-256:", checksum)
            return 0
        secret = _passphrase("Encrypted PRIVATE HUMAN history passphrase")
        data, html = _read_vault(args.vault, secret)
        del secret
        if args.action == "inspect":
            print("Authenticated local ciphertext, NOT authenticated human owner/client identity.")
            print("Source records:", data["source_record_count"])
            print("Operator-ordered snapshots:", data["snapshot_count"])
            print("Latest original records requiring HUMAN followup:", data["latest_attention"])
            print("Contains optional private ID/owner details:", data["includes_private_actions"])
        elif args.action == "open":
            if not args.ack_plaintext_html:
                raise ValueError("must acknowledge decrypted local HTML is UNENCRYPTED")
            dest = _output_path(args.output, ".html")
            _atomic_private_publish(dest, html)
            print("Created new PRIVATE UNENCRYPTED static HTML, verify recipient separately.")
        else:
            checksum = _save(args.output, data)
            print("Created newly encrypted source-identical HUMAN history; original vault untouched.")
            print("New unsigned ciphertext SHA-256:", checksum)
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN history HOLD: source, ciphertext, privacy acknowledgment or output invalid.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
