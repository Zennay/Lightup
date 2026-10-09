# Evidence identifier canonicalization — UUID4 offline reference

## Verified source observation

On current `main` (base `dd4072cdd1a2bc44a752ccbb7b1d0b6d56559da1`),
`src/lightup/state.py` issues IDs inside `StateStore.add_evidence()` by
`str(uuid4())`. The evidence table uses `evidence_id TEXT PRIMARY KEY`;
the SHA-256 of payload bytes is stored **separately**. Evidence ID is not a
content hash. This corrects an earlier illustrative `ev-<sha256>` reference,
which is not compatible with this issuer.

## Offline lexical reference contract

Accepted: exact built-in `str`, 36 ASCII characters, lowercase hyphenated
RFC 4122 UUID version 4, RFC variant `8`/`9`/`a`/`b`. Every other input
fails with the same `ValueError("noncanonical evidence identifier")`.

Rejected: uppercase aliases, UUID URNs, braces, hyphenless aliases, alternative
versions and variants, Unicode lookalikes, invalid separators, control characters,
wrong lengths, other object types and `str` subclasses. No coercion, trimming
or automatic conversion occurs. Two valid UUID4 values retain distinct identity.

## Boundary and caveats

This is a **reference**, not an enforcement patch. Some historical producers,
fixtures and persistence pathways may use different IDs; inventory them before
deploying an exact-format check. Do not migrate or reinterpret existing rows
silently. Lexical UUID4 shape cannot prove issuer authenticity, row existence,
tenant ownership, run membership, payload hash, provenance or authorization.

The production evidence owner must separately enforce tenant/run/capability
binding and integrity before read, export, remediation or retest, with explicit
backward compatibility policy. This PR does not edit production code.

## Promotion gate

Source-owner compatibility review; exact-head hosted tests; exact-head
permanent self-hosted VPS validation; explicit human review. None is claimed
green here. There are no target network calls, DNS, scanner invocations,
authorization changes or deployments.
