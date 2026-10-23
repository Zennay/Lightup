#!/usr/bin/env python3
"""Strict private multi-agenda human proposal bundle admission (no authority)."""
from __future__ import annotations
from hashlib import sha256

from portfolio import FLAGS, Hold, MAX_BYTES, decode_json, encode, read_regular
from archive import reject_authority

SCHEMA = "lightup.assessment_portfolio_human_proposal_bundle.v1"
PROPOSAL_SCHEMA = "lightup.assessment_portfolio_human_proposal.v1"
MAX_BUNDLE = 4 * 1024 * 1024
FIELDS = {"schema", "reference_date", "source_count", "sources",
          "planning_not_permission", *FLAGS}
SOURCE_FIELDS = {"slot", "source_agenda_sha256", "proposal"}
PROPOSAL_FIELDS = {"schema", "source_agenda_sha256", "reference_date",
                   "source_count", "items", *FLAGS}


def load(path, mapping, agendas, *, raw=None):
    if raw is None:
        raw = read_regular(path, MAX_BUNDLE)
    elif type(raw) is not bytes or not 0 < len(raw) <= MAX_BUNDLE:
        raise Hold("invalid complete in-memory private human bundle")
    document = decode_json(raw)
    reject_authority(document)
    count = mapping["source_count"]
    if (type(document) is not dict or set(document) != FIELDS
            or document["schema"] != SCHEMA
            or document["reference_date"] != mapping["reference_date"]
            or document["planning_not_permission"] is not True
            or type(document["source_count"]) is not int
            or document["source_count"] != count
            or type(document["sources"]) is not list
            or len(document["sources"]) != count
            or any(document[f] is not False for f in FLAGS)):
        raise Hold("not a private original human proposal bundle")
    validated = []
    for index, (source, raw_agenda) in enumerate(zip(document["sources"], agendas), 1):
        digest = sha256(raw_agenda).hexdigest()
        if (type(source) is not dict or set(source) != SOURCE_FIELDS
                or type(source["slot"]) is not int or source["slot"] != index
                or type(source["source_agenda_sha256"]) is not str
                or source["source_agenda_sha256"] != digest):
            raise Hold("human proposal bundle source differs from original workspace")
        proposal = source["proposal"]
        if (type(proposal) is not dict or set(proposal) != PROPOSAL_FIELDS
                or proposal["schema"] != PROPOSAL_SCHEMA
                or proposal["source_agenda_sha256"] != digest
                or proposal["reference_date"] != mapping["reference_date"]
                or type(proposal["source_count"]) is not int
                or proposal["source_count"] != mapping["sources"][index - 1]["original_source_count"]
                or type(proposal["items"]) is not list
                or len(proposal["items"]) != proposal["source_count"]
                or any(proposal[f] is not False for f in FLAGS)):
            raise Hold("human proposal bundle has incompatible old source")
        raw = encode(proposal)
        if not 0 < len(raw) <= MAX_BYTES:
            raise Hold("human proposal too large")
        validated.append(raw)
    return validated
