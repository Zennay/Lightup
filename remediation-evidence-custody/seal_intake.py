#!/usr/bin/env python3
"""Seal PRIVATE append-only local fingerprints to a NEW original LightUp HUMAN .ltv.

Uses unchanged original account authorization, encrypted-vault admission and
HUMAN source/record validators. Never mutates owner state or contacts targets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "remediation-evidence-bridge"))
sys.path.insert(0, str(HERE))

import workspace as human
import merge as native
from open_current import _current_rows

MAX_LOCAL_DRAFT = human.LIMIT

def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")

def _admit_delta(old: dict, candidate: dict, ids: set[str]) -> int:
    """An immutable full original HUMAN baseline plus genuinely appended files."""
    if old.get("schema_version") != 2 or candidate.get("schema_version") != 2:
        raise ValueError("Original Unified HUMAN v2 is required for append-only encrypted sealing.")
    # Keep the ENTIRE native HUMAN workspace untouched, including original
    # warning text, exact source binding and every false authority flag.
    before=dict(old);after=dict(candidate)
    before.pop("attachments",None);after.pop("attachments",None)
    if canonical(before)!=canonical(after):
        raise ValueError("Original non-artifact HUMAN content or source claims changed.")
    if type(old.get("attachments")) is not list or type(candidate.get("attachments")) is not list:
        raise ValueError("Original artifact record arrays are required.")
    retained = len(old["attachments"])
    if len(candidate["attachments"]) <= retained or len(candidate["attachments"]) > 120:
        raise ValueError("Expected at least one new LOCAL fingerprint within original native 120-entry bound.")
    if canonical(candidate["attachments"][:retained]) != canonical(old["attachments"]):
        raise ValueError("Original PRIVATE human attachment records changed, reordered or disappeared.")
    fresh = candidate["attachments"][retained:]
    for rec in fresh:
        if type(rec) is not dict or rec.get("human_stage") != "unreviewed":
            raise ValueError("New local fingerprints must remain explicitly HUMAN unreviewed.")
        if type(rec.get("finding_id")) is not str or rec["finding_id"] not in ids:
            raise ValueError("New local fingerprint is not bound to a current original finding.")
    # Original schema admission validates every native record, limit, request,
    # casework and fingerprint, including duplicates per finding and SHA-256.
    native._records(candidate, ids)
    return len(fresh)

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("db", "email", "client-id", "engagement-id"):
        p.add_argument("--" + key, required=True)
    p.add_argument("--previous", required=True, type=Path,
                   help="Existing unchanged original encrypted PRIVATE HUMAN workspace .ltv")
    p.add_argument("--draft", required=True, type=Path,
                   help="Owner-only 0600 PRIVATE Unified v2 JSON exported by offline custody intake")
    p.add_argument("--output", required=True, type=Path,
                   help="NEW encrypted 0600 PRIVATE HUMAN .ltv under trusted owner-only 0700 directory")
    p.add_argument("--ack-private-intake", action="store_true", required=True,
                   help="Explicit HUMAN awareness of original source and privacy boundaries")
    opt = p.parse_args(argv)
    try:
        if not opt.ack_private_intake or not sys.stdin.isatty():
            raise ValueError("Explicit human consent to local PRIVATE processing and private TTY required.")
        if (opt.previous.suffix.lower() != ".ltv" or opt.draft.suffix.lower() != ".json"
            or opt.output.suffix.lower() != ".ltv"):
            raise ValueError("Exact original .ltv, PRIVATE JSON draft and new encrypted .ltv output required.")
        a,b,c=(x.expanduser().absolute() for x in (opt.previous,opt.draft,opt.output))
        if len({a,b,c}) != 3:
            raise ValueError("Never overwrite or alias original PRIVATE records or draft JSON.")
        # Authenticate once against the actual installed original LightUp
        # DomainStore: current user/tenant/engagement read, not a live scan.
        current = human.bridge.original._authorized_summary(
            db=opt.db,email=opt.email,
            client_id=opt.client_id,engagement_id=opt.engagement_id)
        original_csv = current.encode("utf-8","strict")
        digest, count = human._native_digest(original_csv)
        original_ids = _current_rows(original_csv)
        vault = human.bridge.original._vault()
        encrypted = vault._private_input(a, vault.MAX_VAULT)
        original_password = vault._password("Original encrypted HUMAN workroom passphrase: ",fresh=False)
        original_payload, mime, _ = vault._open(encrypted, original_password)
        if mime != "application/json":
            raise ValueError("Existing PRIVATE HUMAN source vault has unexpected MIME.")
        metadata, original_envelope_csv, original_human = human._admit_workspace(original_payload)
        if (original_envelope_csv != original_csv or metadata["client_reference"] != opt.client_id
            or metadata["engagement_reference"] != opt.engagement_id
            or metadata["original_finding_count"] != count
            or metadata["original_source_digest"] != digest):
            raise ValueError("Original encrypted HUMAN source is not today's current authorized original source.")
        old = human._packet(original_human, source_digest=digest,count=count,
                            client=opt.client_id,engagement=opt.engagement_id)
        native._records(old, original_ids)
        requested = vault._private_input(b,MAX_LOCAL_DRAFT)
        candidate = human._packet(requested,source_digest=digest,count=count,
                                   client=opt.client_id,engagement=opt.engagement_id)
        appended = _admit_delta(old,candidate,original_ids)
        packed = human._make_workspace(original_csv, requested,
                                      opt.client_id,opt.engagement_id)
        replacement = vault._password("New PRIVATE HUMAN intake vault passphrase: ",fresh=True)
        if replacement == original_password:
            raise ValueError("New encrypted output needs a different private passphrase.")
        sealed = vault._seal(vault._inner(packed,"application/json"),replacement)
        vault._exclusive_output(c,sealed)
        print("Created NEW owner-only encrypted 0600 PRIVATE HUMAN .ltv; existing source and draft unchanged.")
        print("Original preserved fingerprints:",len(old["attachments"]),"; newly appended HUMAN unreviewed:",appended)
        print("Existing original Casework, Evidence Review and HUMAN follow-up requests preserved verbatim.")
        print("No original owner state update, grant, consent, scan, network target, retest or remediation verdict.")
        return 0
    except Exception:
        print("HUMAN HOLD: No encrypted intake output created. Check original authorized tenant/engagement, owner-private files and unchanged HUMAN baseline.",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
