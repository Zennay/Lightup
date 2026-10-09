# Evidence receipt tenant/run/finding binding — offline reference

Status: **reference only; not wired to LightUp production.** This tests/docs-only slice is independent of the current StateStore, finding persistence, export, hash and remediation-owner branches.

## Required admission semantics

A finding's evidence receipt must remain bound to its *exact* originating tenant, run, finding and content digest at consumption. A valid-looking evidence ID alone is insufficient. A consumer must reject any mismatch before producing a customer-visible verified finding, remediation assertion, retest verdict or export. Rejected inputs must not be auto-repaired, remapped, duplicated, silently downgraded or forwarded to a verifier as trusted.

The included pure Python reference uses an immutable receipt and exact built-in types, and checks revoked state and each of the four binding fields. Tests cover cross-tenant/run/finding substitutions, digest mismatch, revoked/truthy alias, malformed selector inputs, subclass/duck replacement and immutability. The successful reference case means **only conditional shape/binding eligibility**, not trustworthy evidence.

## Production-owner handoff

A source owner must establish authenticated issuer lineage and persisted evidence existence; enforce authorization and tenant scoping independently; validate digest against actual immutable evidence bytes; check current revocation and live scope; and ensure evidence cannot be reassigned by mutable database fields. Document legacy compatibility before strict admission and test that failures perform zero persisted mutations. A digest string equality check is **not** cryptographic verification.

Integrate only with owner coordination, then require exact-head hosted and canonical permanent VPS verification before promotion. Do not call external targets, DNS, services, assessment scanners or active capabilities as part of this reference.

## Adversarial compatibility / limitations

The expanded reference tests exercise exact 256-character length acceptance, 257-character rejection, malformed built-in types in every receipt field and consumer selector, plus case/whitespace alias rejection. The fixture deliberately demonstrates a **coherently forged** receipt: changing both its tenant and the consumer selector passes this shape-only model. This is a **negative trust result**, not a successful provenance check.

The production admission boundary must bind receipts to an independently authenticated tenant/run/finding source, trusted issuer identity, immutable content bytes and evidence-store ownership rather than relying on attacker-supplied matching strings. Cross-tenant reassignment must be prohibited even when all fields agree. Keep this PR draft while this is unresolved.

## Independently registered ledger reference

A second offline test module, `tests/test_evidence_trusted_ledger_reference.py`, illustrates the stronger boundary with server-owned in-memory registrations. The consuming caller supplies only a receipt ID and selectors; a separate ledger resolves the authoritative receipt and matches tenant, run, finding, digest and issuer. Unknown IDs, altered selectors, revoked records and substitute record types fail closed. This is **not** an implementation of durable storage, trusted issuer authentication or cryptographic digest verification. Production must use its existing durable records and owners; this in-memory model is illustrative only.
