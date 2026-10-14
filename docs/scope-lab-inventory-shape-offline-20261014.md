# Lab inventory intersection — offline, explicitly non-authorizing (#103)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

The additive reviewer `scripts/check_scope_lab_inventory_offline.py` is a
**textual comparison tool** for manually declared lab IP address literals
versus proposed literal strings. It does not verify that any declaration,
operator, host, machine, identity, consent document, private network,
time window or security testing request is real or authorized. It is not
wired to LightUp's `ScopePolicy`, `ActivationGate`, the executor, HTTP
pipeline, scanner, workflows, external models or permanent VPS.

## Input

Pass a single ASCII JSON object of at most 8192 bytes through standard
input, with **exactly** three members:

```json
{
  "schema_version": 1,
  "declared_lab_literals": ["127.0.0.1", "10.1.2.3", "fd00::1"],
  "proposed_literals": ["10.1.2.3"]
}
```

Collections must be exact JSON arrays of **1–32 unique canonical bare IP
literal strings**. The reviewer uses the separate literal-class shape
checker on this branch; both collections must contain only syntactically
reviewable loopback, RFC1918 or assigned `fd00::/8` addresses. Any
undocumented special-use, out-of-inventory, duplicate, IPv4-mapped,
noncanonical, hostname, port, URL, CIDR or zone-tagged text yields
whole-input HOLD; no partial approval is emitted. IPv6 spelling must
exactly match `str(ipaddress.ip_address(text))`.

The JSON reader refuses duplicate object keys, nonfinite JSON
constants, malformed encodings, oversized inputs, extra keys, false
`schema_version` booleans and missing values. No customer IDs, raw
IP addresses, tenancy details or authorization claims are included in
the **fixed-schema** output. Every one of
`authorization_verified`, `permit_issued`, `execution_enabled`,
`merge_approved` and `release_approved` is **always false**.

## Synthetic local invocation

```sh
printf '%s\n' '{"schema_version":1,"declared_lab_literals":["10.1.2.3"],"proposed_literals":["10.1.2.3"]}' |
  python3 scripts/check_scope_lab_inventory_offline.py
python3 -m unittest discover -s tests -p 'test_scope_lab_inventory_offline.py' -v
```

`REVIEW_ONLY` has **nonzero exit code 3**; HOLD has exit code **2**.
This is intentional: shell `&&` chains must never take a syntactic
review as scan permission. Do **not** invert return codes to build
an execution gate. Local-only analysis: no DNS, sockets, file writes,
target communication, capability grants, state mutations or auth lookup.

## Required production path, intentionally NOT implemented here

The original source owner [#100](https://github.com/Zennay/Lightup/pull/100)
owns any real private-lab trust decision. A declared offline list is
**untrusted self-report**, not an authoritative or signed scope inventory.
A production admission must independently verify tenant, asset, explicit
consent, allowed capabilities, permitted window, revocations and live grant
bindings; safe DNS/routing semantics and source-owner integration also need
review. The opt-in reviewer cannot attest snapshot authenticity,
trusted chronology, customer identity or machine execution, regardless
of whether it reports REVIEW_ONLY.

Require independent security/privacy/source-owner review, exact immutable
hosted Python 3.11/3.14 and permanently registered VPS test evidence plus
explicit human release before any production use. Current work remains
**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGETS**.
