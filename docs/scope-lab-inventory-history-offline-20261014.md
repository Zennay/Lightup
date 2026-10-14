# Offline lab IP inventory version-history monotonicity review (#103)

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

This third, opt-in, non-authorizing inventory review catches **transient
scope widening** in a short, explicitly supplied sequence even when a later
revision reverts the change. It is an offline comparator of *untrusted
texts*, not an authenticated audit log or a permission gate.

## Strict syntax and boundary

Up to 8192 bytes of ASCII JSON via stdin, with exactly:

```json
{
  "schema_version": 1,
  "lab_literal_versions": [
    ["127.0.0.1", "10.1.2.3", "fd00::1"],
    ["127.0.0.1", "10.1.2.3"],
    ["10.1.2.3"]
  ]
}
```

The `lab_literal_versions` array must contain **2–4 version lists**.
Each list must contain **1–32 unique, canonical, reviewable bare
IP literals**, using the sibling source's narrow loopback/RFC1918/fd00::/8
shape classes. No URL, CIDR, hostname, ports, mapped IPv6, link-local
or special-use addresses are accepted.

Each version must be a subset of its immediate predecessor. **Any
intermediate widening means whole-history HOLD**, even if the last
version is again identical to the first. Missing/extra fields, duplicate
JSON keys, invalid encodings, false version types, malformed previous
contents and huge inputs also HOLD.

Fixed minimal result only: REVIEW_ONLY or HOLD plus a fixed reason and
five always-false authority fields. It does not print tenant, owner,
address, target, permission reference or submitted version contents.
Both results have **nonzero CLI exit codes** (3 and 2 respectively)
to prevent conditional shell execution.

```sh
printf '%s\n' '{"schema_version":1,"lab_literal_versions":[["10.1.2.3","10.1.2.4"],["10.1.2.3"]]}' |
  python3 scripts/check_scope_lab_inventory_history_offline.py
python3 -m unittest discover -s tests -p 'test_scope_lab_inventory_history_offline.py' -v
```

## Limitations: this cannot establish real authorization

The tool does **not** authenticate who supplied versions, completeness
of the sequence, timestamps, ordering, evidence signatures, assets,
tenant ownership, approval, consent, risk classification, execution
windows, revocation or current policy. Missing historical versions can
conceal a real widening, and historical snapshots can be forged.
REVIEW_ONLY means only that the given four-or-fewer **strings** agree.

No DNS, sockets, target probes, grant issuance, scanner, LightUp runtime
imports, deployment, filesystem writes or persistent state mutations.
Source-owner [PR #100](https://github.com/Zennay/Lightup/pull/100),
security/privacy reviewers, exact-head GitHub hosted and genuinely
registered permanent VPS runs, compatibility check and explicit human
release remain strictly required before any production integration.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGETS.**
