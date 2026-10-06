# Evidence-remediation strict parser input purity

Issue: #323

## Purpose

Persisted evidence-remediation payloads are caller-owned data. A strict parser may validate, normalize into new immutable typed values and recompute digests, but it must not sort, pop, rewrite or otherwise mutate the dictionary/list graph supplied by its caller.

This tests/docs-only invariant complements the per-artifact snapshot-isolation work: snapshot isolation proves the returned typed artifact is detached from persisted input; parser input purity proves the parser itself is side-effect-free while decoding that input.

## Covered boundaries

The exact PR #98 ancestry contains and this regression exercises:

1. evidence collection request strict parsing;
2. evidence freshness-constraints strict parsing;
3. evidence freshness-admission strict parsing;
4. evidence-sufficiency attestation strict parsing;
5. classification-review request strict parsing.

Each case uses the repository's real producer fixture and its canonical JSON-decoded payload.

## Invariant

For every covered parser:

- deep-copy the complete nested payload before parsing;
- parse the original caller-owned payload successfully;
- require the payload to remain deep-equal to its pre-parse copy;
- parse the exact same payload a second time;
- require the payload to remain unchanged again;
- require both parsed typed artifacts to equal the real producer artifact;
- require deterministic typed JSON output.

This rejects future implementation changes that obtain canonical ordering by mutating input lists in place, consume fields with `pop()`, replace nested dictionaries, or otherwise leave caller-visible side effects.

## Authority stop line

Input purity does not create new workflow meaning. Collection requests remain planning-only, freshness remains freshness-only, attestation review eligibility remains distinct from LightUp classification selection, and a classification-review request still does not select a classification or create a transition resolution.

No collection/tool/target/execution/remediation/retest/deployment/attack-path authority is introduced and the security verdict remains unevaluated.

## Collision boundary

This slice adds only:

- `tests/test_evidence_remediation_parser_input_purity.py`;
- `docs/evidence-remediation-parser-input-purity.md`.

It does not modify any producer, strict parser, live validator, persisted consumer, existing handoff test or active snapshot sibling.

## Safety

Pure offline/in-memory persistence-integrity testing. No evidence collection, model invocation, network or target interaction, classification selection, tool execution, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation occurs.
