# M7/ST5 scope authorization — duplicate JSON key boundary (offline reference)

Status: **DRAFT / NOT production authorization evidence**. Owner integration: scope authorization and executor owners; do not treat this parser as a grant verifier.

## Threat
JSON objects may carry repeated member names. Last-wins and first-wins decoders can disagree about tenant, decision, scope, revocation, approval, or grant claims. An authorization boundary must reject duplicate object keys **recursively before any authorization interpretation**. This includes keys equivalent after JSON escape decoding (for example `tenant` and `t\\u0065nant`).

## Acceptance criteria
1. Reject duplicate member names at every nesting level, including objects within arrays.
2. Reject decoded-equivalent key aliases; never normalize a duplicate into a grant.
3. Reject nonfinite JSON constants and malformed/non-object envelope values.
4. Validate strict schema separately after parsing: unknown fields, case variants, mixed-type claims, claim signatures, grant provenance, tenant, asset, expiry, revisions, revocation, audit and per-dispatch live status must each fail closed.
5. Never infer authorization from successful JSON parsing, from an offline reference test, or from a correlation identifier.
6. Negative paths must produce no capability dispatch, target network operation, or partial scope allowance; audit failure is also denial.

## Evidence handoff
Run `python -m unittest discover -s tests -p 'test_scope_auth_duplicate_json_keys_reference_20261008.py' -v` at the exact proposed commit. This standalone oracle is deliberately not wired into production. Production owners must add source-integrated parser tests and demonstrate consistent rejection at admission, persistence/replay, queue pickup, retry and dispatch boundaries. Exact-head hosted CI and permanent VPS evidence, owner review and a human release decision remain required before promotion.

## Ownership and safety
Additive tests and document only. Does not edit production grant issuance or activation, executor #107, revocation #983/#989, approval #992, release evidence #982, or other workers' branches. No real targets, scanning, DNS, sockets, new grants, workflow dispatch, merge or deploy.
