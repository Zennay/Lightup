# ST5 remediation authoring-request persisted scalar types

Issue: #658  
Source owner: #198  
Mode: tests/docs-only expected RED

## Contract

The strict persisted remediation authoring-request boundary must accept the exact
scalar runtime types that canonical JSON decoding produces and reject
producer-impossible subclasses before equality, enum conversion, iteration,
length checks, digest validation, or typed reconstruction can observe them.

The acceptance regression exhaustively covers every persisted non-boolean
scalar family in the #198 schema:

- all top-level string fields: schema/future/verdict metadata, client/twin/
  changeset identifiers, and report/plan/bundle/request SHA-256 values;
- all top-level integer fields: current/future twin versions and item count;
- all item scalar strings: change/subject/resolution IDs, resolution and
  evidence-manifest SHA-256, classification and requested output;
- one element in each item string-list field:
  `current_attack_path_ids`, `effect_ids`, and `capability_ids`;
- all nested evidence strings: evidence/run/capability IDs, kind and SHA-256.

Boolean authority/lifecycle fields are already identity-checked with
`is True`/`is False`; Python also does not permit subclassing `bool`.
They therefore do not need an expected-RED subclass case.

Canonical producer JSON remains green. Rejected caller-owned payloads must stay
unchanged.

## Expected RED

At exact #198 head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`, helper validation uses
`isinstance(value, str/int)`; fixed strings are compared by value; and
classification is reconstructed through Enum conversion. Equal-content
subclasses can therefore pass validation even though canonical JSON persistence
cannot produce those runtime types.

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
