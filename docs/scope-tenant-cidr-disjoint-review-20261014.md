# Opt-in cross-tenant lab CIDR inventory collision review

**LightUp: INCUBATE M3/M7 — PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**

This standalone offline check is an **additional denial-only planning aid**
for [scope-authorization issue #103](https://github.com/Zennay/Lightup/issues/103).
It does not extend or install the original source owner's
[PR #100](https://github.com/Zennay/Lightup/pull/100), the existing offline
literal inventory branch, the real grant logic, or any active adapter.

## Safety requirement

A private address block is not proof of ownership, and two tenants can
self-declare overlapping lab subnets. This aid identifies those overlaps in
**one untrusted input document**, so a reviewer can HOLD a potentially
ambiguous plan. It does not prove an inventory is accurate or complete.
It must not determine permission to test any address.

## Strict input

One ASCII JSON document, at most **32,768 bytes**, via standard input:

```json
{
  "schema_version": 1,
  "networks": [
    {"tenant_id": "ALPHA", "scope_id": "LAB1", "cidr": "10.20.0.0/24"},
    {"tenant_id": "BETA", "scope_id": "LAB2", "cidr": "10.21.0.0/24"},
    {"tenant_id": "ALPHA", "scope_id": "V6", "cidr": "fd10:20::/48"}
  ]
}
```

- Exactly 1–64 records, each with **only** `tenant_id`, `scope_id`
  and `cidr`. Tenant and scope IDs are exact built-in ASCII strings
  matching `[A-Z][A-Z0-9_-]{0,23}`; they are unverified labels.
- Every CIDR must be canonical textual form with network bits clear;
  no host-bit normalization, URL, DNS name, port, zone ID, mapped IPv6,
  Unicode alias or plain individual IP without `/32` or `/128`.
- Only IPv4 ranges fully inside RFC1918 `10/8`, `172.16/12`,
  `192.168/16`, or IPv6 inside the assigned `fd00::/8` ULA half.
  Even this classification proves **nothing** about lab ownership.
- Exact JSON keys and types; duplicate JSON keys, extra purported
  approvals, false schema-version booleans, invalid encoding and
  overlarge inputs cause HOLD.
- No duplicate (tenant ID, scope ID) pair. **Any two overlapping
  CIDRs**, whether within one tenant or between tenants, produce an
  atomic HOLD (no partial result). IPv4 and IPv6 never overlap each
  other. Adjacent, nonoverlapping ranges remain separately reviewable.

## Local synthetic test

```sh
printf '%s\n' '{"schema_version":1,"networks":[{"tenant_id":"A","scope_id":"N1","cidr":"10.0.0.0/24"},{"tenant_id":"B","scope_id":"N2","cidr":"10.0.1.0/24"}]}' |
  python3 scripts/check_scope_tenant_cidr_disjoint_offline.py

python3 -m unittest discover -s tests -p 'test_scope_tenant_cidr_disjoint_offline.py' -v
```

The fixed privacy-preserving JSON receipt has only schema version,
HOLD or REVIEW_ONLY, a fixed reason and five hard-false fields:
`authorization_verified`, `permit_issued`, `execution_enabled`,
`merge_approved`, `release_approved`. Neither tenant names nor
the submitted IPs appear in output. **REVIEW_ONLY exits 3, HOLD exits 2**,
intentionally preventing shell `review && scan` chaining. Do not
reinterpret these exit codes to enable execution.

## Mandatory external validation

A reviewer must separately use trusted, tenant-specific inventory,
proof of explicit ownership/consent, asset bindings, allowable capability
and risk, live grant status, time windows, routing/DNS checks and
revocation. This offline parser never authenticates any of those and
cannot attest that omitted ranges do not exist.

No network, socket, DNS, scan, credential handling, permit, database
state change, CI workflow changes, VPS runner execution, deployment or
production integration is part of this feature. It is not a DNS rebinding
defense or an attestation of real network isolation. Independent
source-owner/security/privacy review, exact immutable HEAD hosted and
permanently registered VPS proof, latest-main compatibility and
**explicit human approval** remain required before any merge or release.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGETS.**
