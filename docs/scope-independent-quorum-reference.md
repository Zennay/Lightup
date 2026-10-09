# Scope authorization: independent-reviewer quorum (offline reference)

This standalone reference models **necessary consistency conditions**, not sufficient permission. An operator cannot approve their own request; at least two **distinct**, issuer-rostered reviewers must positively approve the same tenant, request ID, revision and purpose. Any ambiguous, duplicated, withdrawn, stale, malformed, cross-tenant or untrusted vote denies the *entire* synthetic envelope, including when enough other approvals already pass quorum. Malformed roster entries, request identities and revision types also fail closed. A request for three reviewers must have three distinct reviewers.

## Non-authority boundary

A successful reference predicate **does not** authenticate reviewers, attest an issuer-roster snapshot, establish consent, validate signatures, set a real grant, authorize network access, activate a target, or permit capability dispatch. A mere mutable `frozenset` name list is not a trusted identity provider; production must get issuer-authenticated reviewer identities, separation-of-duties policy, tamper-evident per-revision approval receipts and live revocation/expiry checks from authoritative persisted state. Recheck after policy/roster changes and immediately before dispatch. Never infer authority from cached approval counts, backups, exported reports or this reference.

## Validation

```bash
python -m unittest discover -s tests -p 'test_scope_independent_quorum_reference.py' -v
```

Fourteen offline unittest methods; pure standard library. No socket, DNS, scanning, target, credentials, production executor or grant activation. Integration belongs to the production scope owner (PR #107), not this independent draft PR. Require exact-head Python 3.11 and 3.14 plus permanent VPS self-hosted evidence and owner review prior to promotion; never treat an older commit's CI success as evidence for a newer head.
