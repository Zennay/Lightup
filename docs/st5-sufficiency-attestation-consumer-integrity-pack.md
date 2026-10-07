# ST5 sufficiency-attestation consumer integrity pack

Issue: #772  
Parent consumer: PR #154, exact head `e4c82fe0d311548b3d59e1f4c744a88e114f4b13`

## Purpose

This sidecar closes ordering, caller-input atomicity and read-only acceptance
proof around the persisted sufficiency-attestation consumer without changing
its production source.

The composed boundary must remain:

1. duplicate-key-safe persisted input decoding;
2. the exact strict sufficiency-attestation parser;
3. immediate live validation against the verifier identity, verifier preflight
   and complete upstream evidence-remediation lineage;
4. return of the validated typed attestation only.

## Added proof

- **Fail-fast ordering:** malformed JSON, duplicate keys, non-object JSON,
  unsupported runtime input, strict schema drift and digest drift are rejected
  before the live validator can run.
- **Rejection atomicity:** strict digest rejection and live verifier-identity
  rejection leave the complete caller-owned object value, recursive container
  identities and ordering unchanged across repeated calls.
- **Success atomicity:** repeated valid consumption returns the same canonical
  typed attestation without mutating caller-owned persisted input.
- **Read-only live validation:** success and rejection cannot create runs,
  acquire capability leases or add evidence, and leave existing StateStore rows
  plus live upstream objects unchanged.

## Ownership / non-overlap

PR #154 retains all production consumer ownership. PRs #159/#161 retain the
durable persisted-consumer family gate and persisted runtime-type exactness
ownership. This pack deliberately does not duplicate that type-exactness lane.
It does not modify classification-review, scope authorization, target-capable
workers, remediation/retest execution, deployment, verdicts or attack-path
state.

## Safety stop line

This is persistence-validation proof only. Recorded sufficiency and
justification remain inputs to later review; this package does not select a
classification, resolve a transition, execute tools, interact with targets,
author/apply remediation, retest future state, deploy, or mutate attack paths.
