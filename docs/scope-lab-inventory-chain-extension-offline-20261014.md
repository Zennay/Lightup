# Offline lab checksum-chain extension / rollback review (#103)

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

This independent, opt-in comparison checks the **structure of two
caller-supplied, self-declared** checksum chains. An entirely untrusted
"candidate" must preserve every byte-equivalent (JSON-structure)
revision of the "previous" chain and append at least one additional
strictly narrowing or unchanged revision. It does not verify the
previous chain came from a trusted source, retained all older
revisions, was signed, or represented any customer's actual scope.

## Contract

Input: at most **8192 bytes ASCII JSON** on stdin:

```json
{
  "schema_version": 1,
  "previous_chain": {
    "schema_version": 1,
    "revisions": []
  },
  "candidate_chain": {
    "schema_version": 1,
    "revisions": []
  }
}
```

The `revisions` fields above are **illustrative placeholders only**:
both chains must in reality contain 2–4 complete valid revision
records in the strict format documented by
`docs/scope-lab-inventory-chain-offline-20261014.md`.
They use exact incremental revision indices, consistent SHA-256
checksums, canonical lab-IP literal sets and monotonic narrowing.
A candidate with an equal/shorter length is HOLD, as is any
rewritten prior record (including reordered IP strings),
broken link, invalid address, extra permission field or new
address at any intermediate revision. New appended versions
cannot exceed the offline cap of four records.

```sh
python3 -m unittest discover -s tests -p 'test_scope_lab_inventory_chain_extension_offline.py' -v
```

The output is a minimal, non-identifying review-only or HOLD receipt.
All five authority fields are **always false** and no raw asset,
digest, owner, tenant, consent or private marker is emitted.
`REVIEW_ONLY` exits **nonzero 3**, HOLD exits **nonzero 2**: a
conditional shell action must never interpret either result as
permission to run an actual scan.

## Threat model limitations (critical)

The entire *previous* chain is untrusted and self-supplied.
A malicious submitter can rewrite both chains, recalculate
every SHA-256 checksum, omit older revisions or replay a different
history. This check can detect only inconsistencies in the
**two provided JSON objects**; it is not replay protection,
cryptographic authentication, witnessed inventory evolution, a
digital signature, legal ownership verification, policy enforcement,
a customer grant, an authorization to test or a production release.

Production adoption must involve a separate trusted append-only
ledger/signing mechanism, trusted source-owner assets and
tenancy/grant linkage, revocations, consent and scoped time/capability
windows. Do not treat this helper as the trusted ledger.
No network, DNS, scanner, target interaction, database mutation or
real permission issuance exists in this feature. Source-owner
[#100](https://github.com/Zennay/Lightup/pull/100) still owns the
actual authorization policy.

Independent security/privacy review, exact-head hosted
Python3.11/3.14 tests, actual permanently registered VPS CI and
explicit human approval remain mandatory before any merge or deploy.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGETS.**
