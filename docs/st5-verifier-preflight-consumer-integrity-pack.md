# ST5 verifier-preflight consumer integrity pack

Issue: #770  
Parent consumer: PR #150, exact head `05fa52659f7b7d44bc87d737429d6e719e9a769a`

## Purpose

This sidecar closes ordering, caller-input atomicity and read-only acceptance
proof around the persisted sufficiency verifier-preflight consumer without
changing its production source.

The composed boundary must remain:

1. duplicate-key-safe persisted input decoding;
2. the exact strict verifier-preflight parser;
3. immediate live validation against the current verifier identity and full
   evidence-remediation lineage;
4. return of the validated typed preflight only.

## Added proof

- **Fail-fast ordering:** malformed JSON, duplicate keys, non-object JSON,
  unsupported runtime input, strict schema drift and digest drift are rejected
  before the live validator can run.
- **Rejection atomicity:** strict digest rejection and live verifier-identity
  rejection leave the complete caller-owned object value, recursive container
  identities and ordering unchanged across repeated calls.
- **Success atomicity:** repeated valid consumption returns the same canonical
  typed preflight without mutating caller-owned persisted input.
- **Read-only live validation:** success and rejection cannot create runs,
  acquire capability leases or add evidence, and leave existing StateStore rows
  plus live upstream objects unchanged.

## Ownership / non-overlap

PR #150 retains all production consumer ownership. PRs #159/#161 retain the
durable persisted-consumer family gate and persisted runtime-type exactness
ownership. This pack deliberately does not duplicate that type-exactness lane.
It also does not modify attestation, classification-review, scope
authorization, target-capable workers, remediation/retest execution,
deployment, verdicts or attack-path state.

## Safety stop line

This is persistence-validation and verifier-eligibility proof only. It does not
make a sufficiency decision, select a classification, resolve a transition,
execute tools, interact with targets, author/apply remediation, retest future
state, deploy, or mutate attack paths.
