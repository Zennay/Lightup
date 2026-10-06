# ST5 remediation snapshot-isolation contract

Issue: #269

This contract sits above the direct-constructor integration gate in #263 and is intentionally tests/docs-only.

## Invariant

The eight original/revised top-level remediation artifacts are immutable planning records. Their public `as_dict()` method returns a serialization snapshot, not a live authority-bearing view.

The regression contract proves:

- repeated `to_json()` calls are byte-for-byte deterministic and match the repository's canonical compact/sorted JSON encoding;
- mutating a returned top-level snapshot cannot change `future_semantics`, `security_verdict`, or later serialized output on the source artifact;
- nested authoring-item and evidence-reference dictionaries produced by `as_dict()` are detached copies;
- nested original/revised review-check dictionaries produced by `as_dict()` are detached copies;
- a mutated snapshot cannot poison the canonical JSON retained by the source artifact;
- the untouched canonical JSON still round-trips through the corresponding strict parser after snapshot mutation;
- independently requested snapshots do not share their top-level dictionary.

## Boundary

This proof does not change production source and does not relax strict persisted schemas. It deliberately does not implement #268's authoring-request `as_dict()` representation-compatibility change.

No model call, target interaction, network action, scanning, tool execution, remediation or retest execution, deployment, security-verdict creation, or attack-path mutation is performed.

## Stack and promotion

Parent is exact #263 head `76e934848a431208610eed5248b362aedab7c55c`.

Branch: `chatgpt/st5-remediation-snapshot-isolation-20261006`.

Promotion requires exact-head hosted proof plus canonical self-hosted LightUp proof. Keep this branch out of the canonical queue while the existing LightUp self-hosted jobs remain stalled.
