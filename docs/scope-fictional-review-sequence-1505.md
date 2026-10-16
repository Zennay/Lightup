# Fictional handoff sequence review (#1505) — offline only

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a separately owned review aid, deliberately **unwired** from production scope, ActivationGate, ToolExecutor, grants, handlers, scans, jobs, clients and VPS. The pure function resides at `src/lightup/fictional_review_sequence_1505.py`; an **opt-in stdin-only** bounded JSON wrapper is at `src/lightup/fictional_review_sequence_cli_1505.py`. Never import either into an authority/runtime path.

A fictional handoff history can contain complete valid-looking individual copies and still have an omitted step, duplicate/reused packet digest, wrong order, reused case ID or backward timestamp. Pass an **exact builtin tuple** of 2–16 **exact built-in frozen `FictionalHandoff`** records, each with canonical `review-<lowercase ASCII>.example.test` marker, exact consecutive one-based sequence number, distinct 64-character lowercase hex SHA-256 **copy hint**, and UTC `YYYY-MM-DDTHH:MM:SSZ` observed instant. Times strictly increase and span at most 24 hours. The pure reviewer checks two snapshots of four built-in fields and rejects obvious observed changes, not undetectable ABA races.

Result is immutable `ReviewOutcome`: either `HOLD` with **no partial metadata** and count zero, or `REVIEW_ONLY` with fixed small count, with **all four permission fields exactly false** in either case. No raw record or digest is echoed. `REVIEW_ONLY` does **not** mean history completeness, authenticated origin, non-repudiation, integrity of a packet's contents, actual client/operator review, consent, approval, approval quorum or dispatch/release permission. A malicious party can fabricate a fully contiguous fictional sequence: there is **no signing, trusted clock, trusted anchoring, persistence or cross-system validation**. SHA-256 here is only a format-checked copy-integrity hint.

## Optional fictional CLI demo
From the repo root, with local Python3.11+, feed the **literal ASCII canonical JSON** fixture and read **only bounded non-authorizing** JSON. No CLI flag grants rights; exits are **2=REVIEW_ONLY (not permission), 3=HOLD, never 0**:

```bash
PYTHONPATH=src python -m lightup.fictional_review_sequence_cli_1505 < docs/examples/fictional-sequence-1505-valid.json
PYTHONPATH=src python -m lightup.fictional_review_sequence_cli_1505 < docs/examples/fictional-sequence-1505-gap.json
PYTHONPATH=src python -m unittest discover -s tests -p 'test_fictional_review_sequence*_1505.py' -v
```

CLI accepts **1..8192 ASCII bytes**, exact compact JSON key order and unique fields: envelope `{"schema":"fictional_handoff_sequence_v1","records":[...]}`, records in exact `case_id,sequence,packet_sha256,observed_at` order, 2..16 entries. Unknown fields, duplicate keys, field reordering, whitespace, invalid types, raw Unicode/non-ASCII bytes, extra bytes and oversized JSON yield generic HOLD without any input-value echo. CLI only reads stdin and writes a fixed JSON to stdout; no filesystem, environment authority, network, DNS, SQLite, subprocess, scan or permission mutation.

**Nothing authorizes execution.** Never feed real customer/target data. Do not merge/deploy/release; owner/security/privacy review, original production fixes, independently authenticated informed client **and** operator consent, revocation-at-use, exact-head full hosted CI, permanent registered `vps-bb300bba` CI and explicit **human GO** are outstanding. Isolated hosted tests on this draft are **not** original production/security release evidence.

This tool owns only the eight new #1505 paths. Existing #1501 semantic proposal delta, #1503 packet byte-copy, #1484 legacy-permit replay and original production authorization remain with their owners.

## Two-capture comparison — independently copied synthetic history
`review_matching_fictional_captures(capture_a, capture_b)` in the **new independent** `fictional_review_sequence_compare_1505.py` compares two independently supplied, internally valid, 2–16 step fictional capture histories. It returns only non-authorizing `REVIEW_ONLY` when both canonical case IDs, sequences, per-event copy digest *hints*, and timestamps match exactly and remain stable across observed repeated reads. Any mismatch/duplicate/missing step/invalid input returns generic no-echo `HOLD`. Matching copies can be fabricated or jointly manipulated, and this comparison **cannot prove historical completeness, authenticated provenance, cryptographic signatures, client/operator consent or release eligibility**. This is distinct from #1503 single-packet byte copy-integrity and #1501 proposal-content widening. Test using `PYTHONPATH=src python -m unittest discover -s tests -p 'test_fictional_review_sequence*_1505.py' -v`.

## Opt-in two-capture stdin CLI (synthetic only)
A distinct, non-authorizing CLI `python -m lightup.fictional_review_sequence_pair_cli_1505` reads **one** canonical ASCII JSON payload, 1..8192 bytes, with exact ordered keys `schema,capture_a,capture_b` where schema is `fictional_handoff_pair_v1`. Both captures must be individually canonical `fictional_handoff_sequence_v1` envelopes and match in every record. Duplicate keys, unknown fields, Unicode, copied history modifications, missing/extra steps and trailing bytes give generic `HOLD` exit **3** with zero data echoed. Identical, locally consistent wholly synthetic copies give `REVIEW_ONLY` exit **2** with all permission flags false—never approval or exit 0. The two inputs are caller-supplied and **may be jointly forged**. No authenticity, approval, real packet proof or provenance is established.

```bash
PYTHONPATH=src python -m lightup.fictional_review_sequence_pair_cli_1505 < docs/examples/fictional-pair-1505-matching.json
PYTHONPATH=src python -m lightup.fictional_review_sequence_pair_cli_1505 < docs/examples/fictional-pair-1505-divergent.json
```
