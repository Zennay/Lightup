# ST5 metadata-review consumer integrity pack

Issue: #774  
Parent consumer: PR #145, exact head `e2a64382a55289a45cf74aedf6e0f65f04126e04`

## Purpose

This sidecar closes ordering, caller-input atomicity and read-only acceptance
proof around the persisted metadata-contract review consumer without changing
its production source.

The composed boundary must remain:

1. duplicate-key-safe persisted input decoding;
2. the exact strict metadata-review parser;
3. immediate live validation against current admission, evidence metadata,
   candidate context and complete upstream evidence-remediation lineage;
4. return of the validated typed review only.

## Added proof

- **Fail-fast ordering:** malformed JSON, duplicate keys, non-object JSON,
  unsupported runtime input, strict schema drift and digest drift are rejected
  before the live validator can run.
- **Rejection atomicity:** strict digest rejection and live evidence-metadata
  rejection leave the complete caller-owned object value, recursive container
  identities and ordering unchanged across repeated calls.
- **Success atomicity:** repeated valid consumption returns the same canonical
  typed review without mutating caller-owned persisted input.
- **Read-only live validation:** success and rejection cannot create runs,
  acquire capability leases or add evidence, and leave existing StateStore rows
  plus live upstream objects unchanged.

## Ownership / non-overlap

PR #145 retains all production consumer ownership. PRs #159/#161 retain the
durable persisted-consumer family gate and persisted runtime-type exactness
ownership. This pack deliberately does not duplicate that type-exactness lane
or downstream sufficiency-review work. It does not modify classification,
scope authorization, target-capable workers, remediation/retest execution,
deployment, verdicts or attack-path state.

## Safety stop line

This is persistence-validation proof only. Metadata consistency remains
non-authoritative; this package does not evaluate sufficiency, select a
classification, resolve a transition, execute tools, interact with targets,
author/apply remediation, retest future state, deploy, or mutate attack paths.
