# Offline lab-inventory change review: narrowing, never authorization

**LightUp INCUBATE M3/M7 — PLAN/LAB ONLY, DRAFT/HOLD, NO MERGE/DEPLOY/SCANS.**

An intentionally separate, opt-in review tool checks that a proposed list
of literal IP addresses is a **subset** of a previous list. This is
the shape-only companion to the sibling offline literal and inventory
intersection tools in draft [PR #1317](https://github.com/Zennay/Lightup/pull/1317).

## Input contract

Single ASCII JSON object via stdin (at most 8192 bytes):

```json
{
  "schema_version": 1,
  "previous_lab_literals": ["127.0.0.1", "10.1.2.3", "fd00::1"],
  "proposed_lab_literals": ["10.1.2.3"]
}
```

Both collections must contain 1–32 unique *canonical bare IP literals*
in the exact loopback/RFC1918/assigned-ULA text classes. Empty arrays,
missing or extra keys, changed schema types, JSON duplicate keys,
unreviewable/noncanonical literals and any proposed expansion yield
whole-review `HOLD`. Removed addresses or an unchanged set yield only
`REVIEW_ONLY`. An earlier state containing unauthorized or malformed
addresses cannot make a new result acceptable. There is no positive
test of legal ownership, a permit or actual current inventory state.

The implementation reuses the standalone inventory parser and literal
validator without touching production `ScopePolicy`, `ActivationGate`,
tool execution, persistent grant state or another worker's paths. All five
authority flags are unconditionally false. Both outcomes have nonzero
exit status: **3 for REVIEW_ONLY, 2 for HOLD**, so `&&` cannot treat
the review as scan authorization. Fixed receipt contains neither source
IP literals nor identifying metadata.

## Synthetic local checks

```sh
printf '%s\n' '{"schema_version":1,"previous_lab_literals":["10.1.2.3","10.1.2.4"],"proposed_lab_literals":["10.1.2.3"]}' |
  python3 scripts/check_scope_lab_inventory_narrowing_offline.py
python3 -m unittest discover -s tests -p 'test_scope_lab_inventory_narrowing_offline.py' -v
```

The tests cover actual positive shape-only subsets, extra addresses,
forged authority metadata, malformed reserved/alias addresses, duplicate
values, empty sets, deterministic randomized permutations, no network/DNS,
privacy-preserving CLI receipts, actual nonzero shell behavior, and
repeated call purity. They are intentionally local and synthetic.

## Security limitations / owner handoff

**Neither historical snapshot is authenticated.** A malicious proposer
can falsify the previous list or suppress earlier widening, and the
helper does not verify audit log completeness, timestamps, signatures,
tenant identity, customer consent, expiration or revocation. Reviewer
`REVIEW_ONLY` is a text relationship, not an authorization.
A trusted inventory provider and binding to real customer-owned assets
must be designed and independently audited by production source owner
[#100](https://github.com/Zennay/Lightup/pull/100).

Require exact latest-head hosted Python 3.11/3.14 and permanently
registered VPS logs, independent source/security/privacy review,
latest-main composition and explicit human approval **before any
merge, release or actual target execution**.
