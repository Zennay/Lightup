# Issue #290: Current-main CIDR union oracle (offline only)

**15 October 2026 — INCUBATE M3/M7 / PLAN-LAB ONLY / DRAFT-HOLD.**

The original [issue #290](https://github.com/Zennay/Lightup/issues/290) already has an isolated older acceptance branch, surfaced in [draft PR #1443](https://github.com/Zennay/Lightup/pull/1443). That branch is still 82 commits behind main. This independent extension uses only two **new names/paths on current main**; it neither modifies nor assumes ownership of the older branch's test/documentation files.

## Scope of proof

`tests/test_scope_current_main_cidr_union_oracle_290_20261015.py` is a **seven-method pure in-memory** safety matrix against the actual installed `ScopePolicy.decide` in this checkout. Its own independently constructed `ipaddress` union oracle compares full IP membership without network I/O.

- IPv4 and IPv6 in-network, boundary and immediately adjacent out-of-network literals, including supported bracketed IPv6 targets.
- Reordering and duplicating overlapping network entries cannot change the verdict, for both "synthetic permission fixture present" and absent.
- A missing `Authorization` fixture continues to block any matching public IPv4/IPv6 network.
- Deliberately turning off `require_authorization_for_public` in a **synthetic test policy only** cannot silently widen CIDR membership.
- Malformed CIDR entries in either tuple position cannot be ignored.
- IP families stay disjoint even when there is an applicable allowlist for the opposite family.
- Real scope policy decisions are stable and deny without invoking DNS, socket creation or subprocess execution.

**Authority boundary:** A `FAKE_AUTH` with `NOT-CUSTOMER-CONSENT` reference only exercises the existing pure membership code path. It is *not* verified customer consent, a durable current grant, a real operator approval, a binding to assets/capabilities/tenant or permission to dispatch tools. Successful tests likewise cannot repair installed authorization defects, prove a registered runner/VPS, or support merging/deploying.

## Acceptance workflow

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_current_main_cidr_union_oracle_290_20261015.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

Use existing hosted Python 3.11/3.14 unit+real producer integration jobs; inspect raw logs on exact immutable SHA and separately require permanent registered VPS proof. Independent source-owner/security/privacy review and explicit human approval are still prerequisites. Other open parser/identity gaps #291, #292, #294 and durable #177/#347 are **not** fixed.

**DRAFT/HOLD — NO MERGE, DEPLOY, CUSTOMER TARGET SCAN OR GRANT ISSUANCE.**
