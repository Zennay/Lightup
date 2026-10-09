# Imported authorization snapshots: non-authority contract (offline reference)

LightUp's scope gate MUST reject any attempt to turn an exported report, backup, audit receipt,
test fixture, cached response or copied grant snapshot directly into an executable authorization.
Imported documents are **untrusted evidence**, never a source of new permission.

## Admission contract

1. Treat imported grant metadata as a hint for reconciliation only, not an authorization issuer.
2. Resolve the exact tenant, request, grant identity and revision against independently trusted
   **current durable issuer-owned state**, at the moment of use and again immediately before dispatch.
3. Deny if the issuer cannot be authenticated, the engagement is closed, consent was withdrawn,
   the grant is revoked or inactive, the asset/capability/risk/window differs, or any state is unavailable.
4. The current authorization revision must match exactly. A backup restore, mirrored database,
   stale cache, replayed receipt or exported SHA-256 digest cannot roll back revocation or trust epochs.
5. A digest is useful for integrity correlation **only**; even a matching hash is not consent,
   issuer provenance, signature verification or authority.
6. Keep imported metadata isolated by tenant and never deserialize it as a live domain grant.
   Admission and live dispatch must use the production owner-maintained gate.

## Regression reference

`python -m unittest discover -s tests -p 'test_scope_import_replay_nonauthority_reference.py' -v`

The accompanying pure-stdlib synthetic predicate checks only **necessary consistency**.
Its positive result is *not* authentication or a permission to scan, resolve DNS, open a socket,
issue credentials, run a capability or contact a target. Production owner PR #107 owns the
actual executable authorization boundary; integration requires source-owner review and pinned
Python 3.11/3.14 + permanent self-hosted VPS CI proof.

No real targets, network traffic, grant issuance, active assessment or deployment are involved.
