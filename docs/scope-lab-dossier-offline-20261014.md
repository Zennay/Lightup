# Atomic offline cross-bound lab scope dossier (shape-only)

**LightUp INCUBATE M3/M7 — PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL TARGETS.**

An extra **opt-in local-only** evaluator lets a reviewer submit one
**strictly untrusted** JSON dossier rather than treating six independently
valid-looking review results as though they belonged to the same scope
request. It checks that every sub-review is syntactically REVIEW_ONLY
*and* that all six refer to the same literal, current inventory, prior
inventory and revision sequence. It is not installed into LightUp,
never invokes any active scanner or grant engine, and never confers
customer consent or legal authority.

## Strict one-input contract

Stdin: 8192 bytes maximum, ASCII-only, JSON with **exact** top-level
keys `schema_version=1`, `literal`, `inventory`, `narrowing`,
`history`, `chain`, `extension`. Each subobject follows the strict
format documented by the corresponding standalone tool:

- `literal`: one canonical bare lab IP member of the proposed inventory.
- `inventory`: declared-versus-proposed 1–32 literal membership.
- `narrowing`: previously provided versus newly proposed inventory.
- `history`: 3–4 historical inventory versions; every step narrows.
- `chain`: the exact same 3–4 historical version sets with internal
  domain-separated self-declared SHA-256 checksums.
- `extension`: candidate chain **exactly equals** `chain`; previous
  chain contains exactly its first 2–3 records, preserving that prefix
  unchanged with at least one new narrowing step.

All related address sets must agree: `inventory.proposed_literals`,
`narrowing.proposed_lab_literals`, last `history` version and last
`chain` revision; penultimate history equals narrower's previous
inventory; history versions equal each chain revision set. Unrelated
valid-looking packets, forged approval fields, malformed data,
widening, stale or rewritten checksum histories all HOLD.

## Local synthetic tests

```sh
python3 -m unittest discover -s tests -p 'test_scope_lab_dossier_offline.py' -v
```

The test fixture builds an ordinary synthetic 3–4 version lab
dossier in memory, checks misbinding across the six independent
reviewers, and verifies no socket/DNS, leaked privacy marker,
permission promotion, shell success or any owner grant.

The receipt contains only a fixed reason code, HOLD or REVIEW_ONLY,
schema version and five **always-false** authorization/permit/execute/
merge/release flags. No IPs, owner, tenant, digest, evidence details
or customer input are echoed. REVIEW_ONLY intentionally exits
**3**, HOLD exits **2**, so it cannot permit an active command via
`&&`.

## Limits / release handoff

**All six subdocuments and the checksum history come from the
same untrusted caller.** A submitter can forge mutually consistent
information, regenerate all SHA-256 checksums and provide only
selected versions. A positive syntactic consistency review is NOT
trusted asset inventory provenance, legal consent, an authentic
history, a grant, an activation decision, a scan permission, a
security assessment or human release. Production-source owner
[#100](https://github.com/Zennay/Lightup/pull/100) remains responsible
for any real authorization binding with source-of-truth tenancy,
assets, window, capability and revocation.

No network, DNS, real targets, permissions, state writes, existing
production or other-worker code, workflows, runners or deployment
are touched. Source-owner/security/privacy review, exact-head hosted
tests and **actual registered permanent VPS** evidence plus explicit
human approval remain release blockers.

**DRAFT/HOLD · NO MERGE · NO DEPLOY · NO REAL TARGET SCANS.**
