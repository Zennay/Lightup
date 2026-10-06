# ST5 evidence-remediation parser input purity

Issue #323 adds a cross-stage persistence-integrity invariant above exact PR #98 head `1369e04a33d55a91479d434208cc6064ac55809d`.

## Contract

Strict persisted evidence-remediation parsers must be pure with respect to caller-owned JSON-decoded dictionaries and nested containers. Parsing may construct a new typed artifact, but it must not sort, rewrite, pop, normalize, replace, or otherwise mutate the input graph in place.

The regression uses the real positive classification-review producer chain and covers the strict boundaries already present in the #98 ancestry:

- evidence collection request (#63/#64);
- freshness constraints (#65/#68);
- freshness admission (#70/#72);
- evidence-sufficiency attestation (#93/#94);
- classification-review request (#97/#98).

For every artifact the proof:

1. serializes the real producer artifact and JSON-decodes it into caller-owned containers;
2. deep-copies the payload before parsing;
3. records byte-sensitive JSON ordering plus every nested dict/list object identity;
4. parses through the exact strict persisted parser and requires equality with the original typed artifact;
5. proves deep content, JSON ordering, and nested container identities are unchanged;
6. parses the same payload a second time and proves deterministic output with the same unchanged caller graph.

This complements snapshot-isolation tests. Snapshot isolation proves exported snapshots cannot mutate the typed artifact; this invariant proves the parser itself does not mutate the snapshot supplied by its caller.

## Stop line

All existing planning/eligibility semantics remain fail-closed. Where a covered artifact exposes the fields, classification selection, transition resolution, collection/tool/target/execution authority, remediation/retest authority, deployment authority, and attack-path mutation remain false. Future semantics remain `unresolved` and the security verdict remains `not_evaluated`.

## Safety and collision boundary

This package is tests/docs-only. It adds no producer, parser, consumer, model, scope, activation, target, collection, execution, remediation/retest, deployment, verdict, or attack-path behavior and does not modify active snapshot siblings.

Run the focused regression with:

```bash
python -m unittest tests/test_future_security_evidence_remediation_parser_input_purity.py
```
