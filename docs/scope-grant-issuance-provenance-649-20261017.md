# LightUp #649 — isolated durable issuance provenance acceptance

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is not authorization.**

This draft is based on the exact existing source-owner PR #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37` (not a speculative merge
of unrelated workers). The source owner retains all `src/lightup/domain.py`
changes. This branch adds only one standalone test module, this document and a
new opt-in scoped workflow; it does not edit production code, tools, workers,
other PR branches, existing GitHub Actions, or the persistent VPS checkout.

## Actual bug / threat model

`DomainStore.record_authorization_grant()` calls `.strip()` to check
`approved_by` / `reference`, and then *calls `.strip()` a second time*
when building the durable `AuthorizationGrant` to insert into SQLite.
The annotations do not reject `str` subclasses. A synthetic subclass can
return nonblank text for the check and blank text for storage. The resulting
authorization/audit row can have empty provenance even though the guard ran.
This is a **durable issuance/audit integrity defect**, not proof of authority
to scan or bypass runtime checks. Raw `int` / `None` also raise unexpected
`AttributeError` rather than a deliberate `ValueError`.

## Contract / exact pass criteria

1. Admission requires `type(approved_by) is str` and
   `type(reference) is str` before calling foreign methods.
2. Canonical `str.strip()` must yield nonempty text for both values.
3. Rejected inputs do not add any durable `authorization_grants` row.
4. Successful canonical text is trimmed once and stored without mutation of
   input scope or validity window.
5. No production source change is part of this acceptance branch.
   Source-owner repair and a new review are required separately.

The temporary SQLite fixture uses exclusively fictional client, operator,
asset `unit.example.test`, and grant reference. No real clients, DNS, sockets,
HTTP, active target, scan, handler, external authorization, or consent evidence
are used.

## Reproduction, not release gate

```bash
python3 -I -S -B -m unittest discover -s tests \
  -p 'test_scope_grant_issuance_provenance_649_20261017.py' -v

LIGHTUP_SCOPE649_REQUIRE_SOURCE_FIX=1 python3 -I -S -B -m unittest discover \
  -s tests -p 'test_scope_grant_issuance_provenance_649_20261017.py' -q
```

Connected permitted zSSH `vps-bb300bba` from an **isolated new clone**,
Python **3.14.4**, exact initial HEAD `797c513be70f8179e82fe485f0a11dfbc5a2a68a`:
ordinary suite **10 methods: 4 PASS, 6 source expectedFailures**.
The opt-in strict run gives **4 real FAIL, 2 ERROR** (non-string
`AttributeError`); no unexpected ordinary failures. These source failures
are **not green source behavior**. As soon as the owner repairs admission,
all six must pass as ordinary strict checks. Source-owner CI is independent
from this test-only reviewer result.

## Release and collision fences

- Only new files named with `649_20261017` or `scope649` may be changed.
- PR base is the owner PR #554 branch (do not write to it).
- Full original hosted and **permanent registered** VPS exact-head green CI,
  separate authenticated client and operator consent, revocation at use,
  independent privacy/security review and explicit HUMAN GO are not supplied
  by this change. Historical original #301 fixed-date fixture remains owned
  by draft PR #1452.
- **No merge, deploy, active scan, real asset/target, grant, handler dispatch
  or release.** Human source-owner decision first.
