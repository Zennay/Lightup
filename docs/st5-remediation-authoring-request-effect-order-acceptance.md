# ST5 remediation authoring-request effect ordering acceptance

Issue #668 pins one narrow persisted-integrity invariant above the active
remediation authoring-request handoff in PR #198.

## Invariant

The authoring-request producer inherits canonically ordered effect identifiers
from the already validated remediation evidence bundle. Persisted effect_ids
must preserve that lexical order. A caller must not be able to reverse a
canonical-looking set, recompute request_sha256, and have the strict parser
accept a second serialized representation of the same logical collection.

The regression keeps the canonical producer request green, then builds a
two-or-more-item canonical-looking effect collection, reverses it, recomputes
the request digest, and requires rejection without mutating caller-owned input.

## Ownership boundary

This branch is an acceptance-only child of exact PR #198 head
7f41af2dcbecd84eee7830cae8b05c6acecdb923.

It changes no production source. PR #198 remains the owner for the eventual
minimal parser repair. Existing branches retain ownership of canonical
identifier shape, path/capability semantics, scalar/container exactness,
evidence kind, cross-item lineage, parser purity, and snapshot isolation.

## Safety

This is persistence-integrity coverage only. No model invocation, target
interaction, code/config generation, tool/remediation/retest execution,
deployment, verdict creation, or attack-path mutation is introduced.
