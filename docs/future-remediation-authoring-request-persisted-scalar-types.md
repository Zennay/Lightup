# ST5 remediation authoring-request persisted scalar types

Issue: #658  
Source owner: #198  
Mode: tests/docs-only expected RED

## Contract

The strict persisted remediation authoring-request boundary must accept the exact
scalar runtime types that canonical JSON decoding produces and reject
producer-impossible subclasses before equality, enum conversion, iteration,
length checks, digest validation, or typed reconstruction can observe them.

This acceptance slice covers representative scalar families:

- fixed metadata strings: `schema_version`, `future_semantics`,
  `security_verdict`;
- a top-level identifier and SHA-256 digest;
- a persisted non-negative integer;
- item identifier, classification, requested-output and SHA-256 strings;
- a nested string-list entry;
- evidence identifier, kind and SHA-256 strings.

Canonical producer JSON remains green. Rejected caller-owned payloads must stay
unchanged.

## Expected RED

At exact #198 head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`, helper validation uses
`isinstance(value, str/int)`; fixed strings are compared by value; and
classification is reconstructed through Enum conversion. A subclass carrying
the canonical value can therefore pass validation even though canonical JSON
persistence cannot produce that runtime type.

#198 should absorb exact built-in scalar guards locally and reject rather than
normalize or coerce.

## Collision boundary

This issue does not duplicate:

- #409/#410 canonical identifier shape/order;
- #411/#412 exact evidence-kind semantics;
- #413/#414 capability-set binding;
- #415/#416 positive version semantics;
- #417/#418 classification/current-path shape;
- #419/#420 resolution/effect lineage;
- #421/#422 canonical item/evidence identity content;
- #425/#426 top-level canonical text content;
- #431/#433 cross-item ownership;
- #583 raw JSON exact-text typing;
- #628 mapping/list/schema-key exactness;
- #638 snapshot isolation;
- #640 direct-parser input purity.

No #198 source file is modified.

## Safety

Pure in-memory persistence-integrity acceptance. No model invocation, target
interaction, scanning, remediation generation or execution, retest execution,
deployment, scope-authorization mutation, security verdict creation, or attack
path mutation. Keep this branch PR-less while permanent LightUp CI capacity is
occupied.
