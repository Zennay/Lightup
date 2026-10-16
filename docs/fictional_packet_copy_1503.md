# Fictional scope-review packet copy integrity — #1503 (DRAFT/HOLD)

**LightUp posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is not an approval system.**

`src/lightup/fictional_packet_copy_1503.py` is an **unwired**, opt-in, pure Python-stdlib reviewer. Caller-supplied copies of an already-fictional review packet must be **identical canonical bytes** before a manual operator can mark the *copy* as unchanged. This is not the proposal widening/narrowing checker (#1501), operator notice generator (#1495), free-text privacy quarantine (#1497), or production policy evaluator.

## Exact schema and example

Canonical serialization is ASCII JSON, exact key order, no extraneous whitespace, escaped aliases, duplicate keys, unknown fields or trailing data, and at most **2048 bytes**. This example carries no author identity, real asset, real consent, signature, session, scan, URL or action:

```json
{"schema":"lightup-fictional-copy-v1","asset":"alpha.example.test","message":"REVIEW_REQUIRED","capabilities":["metadata_read","report_preview"],"authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}
```

The `asset` must be a 1–32 character lowercase ASCII single label followed by literal `.example.test` (reserved fictional namespace); pseudo-IDNA prefixes `xn--`, doubled hyphens and trailing hyphens are disallowed. `capabilities` must contain 1–3 unique, lexicographically sorted values from `metadata_read`, `report_preview`, `scope_review`. `message` is only `REVIEW_REQUIRED` or `REVIEW_ON_HOLD`. All four authority flags must literally be JSON `false`.

## Offline use — canonical fictional packet creation and safe fanout

```python
from lightup.fictional_packet_copy_1503 import (
    build_fictional_copy_packet,
    compare_fictional_packet_copies,
    compare_fictional_packet_fanout,
)

source = build_fictional_copy_packet(
    "alpha.example.test",
    "REVIEW_REQUIRED",
    ("metadata_read", "report_preview"),
)
assert type(source) is bytes  # Fictional, not a customer record

pair = compare_fictional_packet_copies(source, source)
recipients = compare_fictional_packet_fanout(source, (source,) * 3)
assert pair.status == recipients.status == "REVIEW_ONLY"
assert recipients.authorized is False and recipients.dispatch_allowed is False
# Corruption of ANY recipient, even the last one, produces only generic HOLD.
assert compare_fictional_packet_fanout(source, (source, source, b"changed")).status == "HOLD"
```

The builder accepts **exact built-in str asset, exact built-in str message and exact built-in tuple of 1–3 sorted allowed str capability identifiers**, and returns `None` on any malformed/caller-subclass input. It hard-codes all four authority flags to JSON false and cannot accept identity, targets, proof, signing credentials or runtime mode. It is not intended for sensitive data.

Fanout accepts **1–16 exact built-in byte strings in an exact built-in tuple** and checks every copy against the same original strictly canonical bytes. There is no per-recipient status, content echo, metadata or partial digest on failure. This is *copy equality*, **not** sequential authorization proposal evolution (#1501). All copies are caller-controlled and neither pair nor fanout authenticates who authored or delivered the packet.

- Invalid or different copies: **HOLD**; digest is `None`; no caller text or partial metadata returned.
- Both exactly canonical and byte-identical: **REVIEW_ONLY** with a lowercase SHA256 fingerprint of the *fictional* bytes. A SHA256 digest alone is **not** signed provenance, tamper resistance against someone who controls both copies, client/operator consent, revocation, or release evidence.
- The immutable result always has `authorized=False`, `consent_verified=False`, `dispatch_allowed=False`, `release_allowed=False`.
- No production module imports or calls this helper. No paths, storage, network, DNS, SQLite, handlers or scans. No actual client assets should be supplied. No CLI that writes or emits review data.

## Reproducible checked-in fictional examples

- `docs/examples/fictional-copy-1503.json` is an **exact canonical no-newline** packet whose bytes the builder reproduces.
- `docs/examples/fictional-copy-changed-1503.json` is a different but still canonical **fictional** packet; comparing it to the first returns atomic generic `HOLD`. Both contain only reserved `.example.test` labels and four literal false authority flags.
- The dedicated hosted test suite reads both committed files as bytes and asserts identical encoding, expected builder equality and fail-closed end-to-end fanout behavior; edits to either example trigger that workflow. Neither file is a real consent record or scope grant.

## Tests and ownership

Run opt-in isolated tests (including exhaustive byte edits, builder invariants, 16-copy fanout, no-I/O tripwires) with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_fictional_packet_copy_1503.py' -v`. Dedicated **hosted** Python 3.11/3.14 workflow `.github/workflows/lightup-fictional-packet-1503.yml` runs only this new test file when the new file set changes. This does not substitute for original full hosted preflight or the genuinely registered permanent VPS runner (#1144). All files exclusively added under #1503; do not cherry-pick as production authorization.

**Release STOP:** Original source owner fixes incl. #301, authentic both-client-and-operator informed consent, runtime revocation-at-use, full exact-head hosted + registered VPS proof, independent security/privacy review and explicit human GO remain open. Do **not** merge, deploy, scan, issue grants, wire any handler or assert approval based on this packet.
