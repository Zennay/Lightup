# ST5 sufficiency-review consumer integrity pack

Issue: #769  
Parent consumer: PR #148, exact head `bc679013a2986bfc949d40e279790862d64dd1b0`

## Purpose

This sidecar closes four acceptance-proof gaps around the persisted
sufficiency-review request consumer without changing its production source.

The composed boundary must remain:

1. duplicate-key-safe persisted input decoding;
2. the exact strict sufficiency-review request parser;
3. immediate live lineage validation;
4. return of the validated typed request only.

## Added proof

- **Fail-fast ordering:** malformed JSON, duplicate keys, non-object JSON,
  unsupported runtime input, strict schema drift and digest drift are rejected
  before the live validator can run.
- **Rejection atomicity:** strict digest rejection and live lineage rejection
  leave the complete caller-owned object value, recursive container identities
  and ordering unchanged across repeated calls.
- **Success atomicity:** repeated valid consumption returns the same canonical
  typed request without mutating caller-owned persisted input.
- **Read-only live validation:** success and rejection cannot create runs,
  acquire capability leases or add evidence, and leave existing StateStore rows
  plus live upstream objects unchanged.

## Ownership / non-overlap

PR #148 retains all production consumer ownership. Existing object-type RED and
snapshot-hosted-validation branches remain separate. This pack does not modify
verifier-preflight, attestation, classification-review, scope authorization,
target-capable workers, remediation/retest execution, deployment, verdicts or
attack-path state.

## Safety stop line

This is persistence-validation proof only. It does not decide evidence
sufficiency, select a classification, resolve a transition, execute tools,
interact with targets, author/apply remediation, retest future state, deploy, or
mutate attack paths.
