# Tenant lab CIDR + UTC window collision review (offline only)

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**

This separate, opt-in *planning* utility reviews whether **self-reported** lab CIDR ranges and UTC window intervals overlap. It is not a grant, authorization, signed time-window record, proof of asset ownership, isolated network attestation, real network routing check, or a scheduled scan.

## Exact input

One ASCII JSON document (at most 32,768 bytes):

```json
{
  "schema_version": 1,
  "windows": [
    {"tenant_id": "ALPHA", "scope_id": "LAB1",
     "cidr": "10.10.0.0/24",
     "starts_at": "2026-10-14T08:00:00Z",
     "ends_at": "2026-10-14T09:00:00Z"},
    {"tenant_id": "BETA", "scope_id": "LAB2",
     "cidr": "10.10.0.0/24",
     "starts_at": "2026-10-14T09:00:00Z",
     "ends_at": "2026-10-14T10:00:00Z"}
  ]
}
```

- Exactly 1–32 records with these five fields and no extra keys; each tenant+scope identity unique; exact ASCII uppercase IDs.
- CIDRs must be canonical, contained entirely in RFC1918 IPv4 or assigned fd00::/8 IPv6 ULA; invalid, public, reserved, mapped/link-local, host-bit and ambiguous CIDRs HOLD.
- Times must be exactly `YYYY-MM-DDTHH:MM:SSZ` (strict ASCII UTC, no fractions or offsets); real calendar dates, half-open interval `[start,end)`, strictly positive duration at most **24 hours**.
- **Atomic HOLD** if any two same-family, overlapping CIDRs have strictly overlapping time windows (even within one tenant). Same CIDR at **adjacent** windows, or disjoint CIDRs at the same time, is syntactically reviewable. No partial permits or per-target acceptance are emitted.
- Strict bounded JSON parser rejects duplicate keys at any depth, nonfinite values, unicode bytes, unknown/forged authority fields, wrong types or oversized input.

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_window_conflicts_offline.py' -v
```

The fixed output never displays any tenant ID, IP literal or timestamp. All five fields `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved` are **false**. **REVIEW_ONLY exits 3, HOLD exits 2**; neither produces successful shell execution for `review && scan`.

**Critical limitation:** Declared CIDRs and periods are entirely untrusted; no true customer consent, timestamp source, policy, grant, revocation, real network ownership, isolation, routing or authorized tooling is checked. Two non-overlapping *self-declared* windows do not authorize execution. Source owner [#100](https://github.com/Zennay/Lightup/pull/100) owns all actual production decisions. No DNS, sockets, tests against real targets, persistent state, UI/CLI integration into production, CI runner or deploy scripts.

Require exact-head hosted unit/integration and separate registered permanent VPS evidence, owner and independent security/privacy review, latest-main composition and explicit human release. **DRAFT/HOLD; NO MERGE/DEPLOY/REAL TARGET ACTIVITY.**
