# Fictional scope-review packet copy integrity — #1503 (DRAFT/HOLD)

**LightUp posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is not an approval system.**

`src/lightup/fictional_packet_copy_1503.py` is an **unwired**, opt-in, pure Python-stdlib reviewer. Two caller-supplied copies of an already-fictional review packet must be **identical canonical bytes** before a manual operator can mark the *copy* as unchanged. This is not the proposal widening/narrowing checker (#1501), operator notice generator (#1495), free-text privacy quarantine (#1497), or production policy evaluator.

## Exact schema and example

Canonical serialization is ASCII JSON, exact key order, no extraneous whitespace, escaped aliases, duplicate keys, unknown fields or trailing data, and at most **2048 bytes**. This example carries no author identity, real asset, real consent, signature, session, scan, URL or action:

```json
{"schema":"lightup-fictional-copy-v1","asset":"alpha.example.test","message":"REVIEW_REQUIRED","capabilities":["metadata_read","report_preview"],"authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}
```

The `asset` must be a 1–32 character lowercase ASCII single label followed by literal `.example.test` (reserved fictional namespace); pseudo-IDNA prefixes `xn--`, doubled hyphens and trailing hyphens are disallowed. `capabilities` must contain 1–3 unique, lexicographically sorted values from `metadata_read`, `report_preview`, `scope_review`. `message` is only `REVIEW_REQUIRED` or `REVIEW_ON_HOLD`. All four authority flags must literally be JSON `false`.

## Offline use

```python
from lightup.fictional_packet_copy_1503 import compare_fictional_packet_copies
review = compare_fictional_packet_copies(copy_before, copy_after)  # exact built-in bytes
assert review.authorized is False and review.dispatch_allowed is False
# review.status is always either HOLD or REVIEW_ONLY
```

- Invalid or different copies: **HOLD**; digest is `None`; no caller text or partial metadata returned.
- Both exactly canonical and byte-identical: **REVIEW_ONLY** with a lowercase SHA256 fingerprint of the *fictional* bytes. A SHA256 digest alone is **not** signed provenance, tamper resistance against someone who controls both copies, client/operator consent, revocation, or release evidence.
- The immutable result always has `authorized=False`, `consent_verified=False`, `dispatch_allowed=False`, `release_allowed=False`.
- No production module imports or calls this helper. No paths, storage, network, DNS, SQLite, handlers or scans. No actual client assets should be supplied. No CLI that writes or emits review data.

## Tests and ownership

Run opt-in isolated tests with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_fictional_packet_copy_1503.py' -v`. Dedicated **hosted** Python 3.11/3.14 workflow `.github/workflows/lightup-fictional-packet-1503.yml` runs only this new test file when the new file set changes. This does not substitute for original full hosted preflight or the genuinely registered permanent VPS runner (#1144). All files exclusively added under #1503; do not cherry-pick as production authorization.

**Release STOP:** Original source owner fixes incl. #301, authentic both-client-and-operator informed consent, runtime revocation-at-use, full exact-head hosted + registered VPS proof, independent security/privacy review and explicit human GO remain open. Do **not** merge, deploy, scan, issue grants, wire any handler or assert approval based on this packet.
