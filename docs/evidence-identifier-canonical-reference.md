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

## Issuer-focused regressions

The offline module additionally samples 32 values from Python's `uuid4()` issuer and checks lossless lexical acceptance. It exhaustively rejects all 15 non-version-4 version nibbles and all 12 non-RFC-variant nibbles. This is a nondeterministic positive compatibility smoke check plus deterministic negative lexical coverage; it does not exercise `StateStore.add_evidence()` or prove durable evidence provenance. Exact-head workflow success is required separately.

## Temporary-SQLite issuer compatibility test

An additional source-connected offline acceptance test imports the real
`lightup.state.StateStore`, creates a **plan_only** run inside a
`TemporaryDirectory` SQLite database and checks that `add_evidence()`
issues a lexically canonical UUID4. It then reads that exact row and proves
its stored SHA-256 digest equals the input payload digest and differs from
the evidence ID. This is real issuer/persistence compatibility in an
isolated local fixture, not a production migration, authorization
decision, tenant proof, active assessment or real-target execution.

Run with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_evidence_identifier_canonical_reference.py' -v`.

## Rejected-alias persistence immutability

A further offline temporary-SQLite regression takes a full stored evidence-row snapshot, rejects the uppercase lexical alias, and verifies the stored row remains byte/value-equivalent with the evidence table still containing exactly one record. This is a **reference parser non-mutation test**, not evidence that production `get_evidence()` currently performs lexical validation: the latter must be separately integrated and reviewed by its source owner.
