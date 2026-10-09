# Scope consent must not transfer across ownership boundaries

Status: **offline reference / DRAFT / HOLD**. This contract does not issue grants, approve scans or activate targets.

An approval for tenant A, engagement A, owner A, asset A and capability A must never become valid for tenant B, a successor engagement, changed owner, reassigned asset, or another capability merely because another identifier remains the same. A new explicit source-owner-confirmed approval is required after ownership transfer. A revision change or revocation independently denies admission.

## Reference acceptance scenarios

The companion test uses an in-memory frozen tuple-shaped consent model and checks:
- exact positive fixture (reference predicate only);
- tenant, engagement and owner crossover denial;
- asset and capability substitution denial;
- stale revision and revoked consent denial;
- strict booleans, integer revision and exact built-in string identity types;
- empty identity and malformed revocation denial.

Run offline: `python -m unittest discover -s tests -p 'test_scope_consent_nontransferability_reference_20261009.py' -v`.

## Production integration obligations (not implemented here)

The trusted source owner must bind approvals to verified tenant, engagement, owning principal, canonical asset, capability, approval revision and revocation generation. Independently revalidate atomically immediately before any target I/O and prohibit inferred transfer on sale, tenant move, reassignment, ownership change or reused asset identifiers. Explicit user authorization and review remain required. Integration must prove **zero executor/evidence handler calls** on denial and cover race conditions on revocation or ownership transfer. No target-facing tests are enabled by this PR.

Do not merge, deploy or activate based on this reference. Require exact-head hosted and canonical permanent VPS CI plus source-owner review of #107/#1128 and revocation #100.
