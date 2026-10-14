# Offline lab inventory checksum-chain consistency (#103)

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

A separate opt-in utility now checks a **self-declared** 2–4 revision
lab-IP inventory checksum chain. It detects an accidentally altered
record or missing/reordered intermediate record *inside the supplied
sequence*, and refuses any temporary increase in the set of reviewed
IP literals, even if subsequently reverted. It is explicitly **not**
a signature, consent record, approval or proof of a complete history.

## Checksum protocol

Input is at most 8192 bytes of strict ASCII JSON from stdin. The
outer object has exactly `schema_version: 1` and `revisions`, which
is an array of **2–4 records**. Each record has exactly:

- `version`: exact integer 1, 2, 3, 4 in contiguous sequence;
- `lab_literals`: **1–32 unique canonical bare IP** literals limited
  to the intentionally narrow textual loopback/RFC1918/fd00::/8 classes;
- `previous_digest`: exact JSON null on first record, and the previous
  record's **lowercase SHA-256 hex** checksum thereafter;
- `digest`: lowercase 64-character SHA-256 of domain prefix
  `LIGHTUP-OFFLINE-LAB-CHAIN-V1` followed by a zero byte, followed
  by canonical ASCII JSON of the sorted `lab_literals` list,
  `previous_digest`, and `version` fields (JSON key order sorted,
  no extra spaces, `ensure_ascii=True`).

Example locally generated (synthetic-only) input:

```sh
python3 - <<'PY' | python3 scripts/check_scope_lab_inventory_chain_offline.py
import json
from scripts.check_scope_lab_inventory_chain_offline import record_digest
versions = [["10.1.2.3", "127.0.0.1"], ["10.1.2.3"]]
rows, parent = [], None
for i, values in enumerate(versions, 1):
    digest = record_digest(i, set(values), parent)
    rows.append({"version": i, "lab_literals": values,
                 "previous_digest": parent, "digest": digest})
    parent = digest
print(json.dumps({"schema_version": 1, "revisions": rows}))
PY
python3 -m unittest discover -s tests -p 'test_scope_lab_inventory_chain_offline.py' -v
```

**Warning:** This prints a REVIEW_ONLY receipt but intentionally exits
code **3** (HOLD exits 2). Neither exit code is zero; this must never
be chained with scanner/target actions. The JSON receipt is minimal,
contains no IP literal, owner, tenant, digest or claimed permission,
and has all five authority fields hardwired to **false**.

## What this detects

- Breaks in *supplied* checksum links, sequence-number gaps,
  duplicate/unknown schema fields and modified supplied record text
  where the checksum was not recomputed;
- Widened lab-address sets between any two adjacent supplied versions,
  including expansions hidden by a later textual revert;
- Malformed or ambiguous special-use, noncanonical, duplicate,
  non-ASCII, malformed JSON or oversized input, always atomically HOLD;
- Shell chaining ambiguity, via nonzero REVIEW_ONLY and HOLD results.

## Critical limits / production-owner handoff

**An adversary can regenerate the entire digest chain.**
Checksums do not prove authenticity, that the first entry is trusted,
that omitted earlier revisions do not exist, trusted chronology or
unrevoked legal consent. This tool does not read a signed audit ledger,
verify a tenant, inspect current grants, issue permissions, access
networks/targets or change persistent state. Even a perfectly
consistent chain is no evidence that the caller owns any lab address.

Any production integration and attestation would require an independently
trusted signing/retention mechanism, tenant and asset bindings, allowed
capabilities/time ranges, revocation, source-owner [#100](https://github.com/Zennay/Lightup/pull/100),
privacy/security audit, exact-head Python3.11/3.14 hosted + registered
permanent VPS evidence, and explicit human release.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGET ACTIVATION.**
