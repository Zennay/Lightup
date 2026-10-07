# Persisted authorization-grant provenance integrity

Issue: #475  
Source owner: PR #142  
Exact acceptance base: `f6214a1dc3b2a86780e1b1d04d8e0803947e61ba`

## Purpose

Grant issuance requires a non-empty approval actor and authorization reference. Execution-time revalidation must not trust a durable row that has drifted into a state which issuance would reject.

This branch reserves that invariant without modifying the active domain source-owner stack.

## Contract

For target-active execution resolution:

- canonical persisted `approved_by` and `reference` remain accepted;
- empty or whitespace-only persisted `approved_by` is non-executable;
- empty or whitespace-only persisted `reference` is non-executable;
- invalid provenance produces no executable grant;
- revalidation must not trim, rewrite, or otherwise repair the durable row as a side effect.

This is deliberately narrower than #177, which owns request→grant approval provenance, and separate from #299, which covers the older legacy `models.Authorization` object.

## Acceptance cases

`tests/test_scope_authorization_persisted_grant_provenance.py` contains one canonical positive control and four expected-RED durable-drift cases:

1. blank `approved_by`;
2. whitespace-only `approved_by`;
3. blank `reference`;
4. whitespace-only `reference`.

The expected repair belongs in #142's execution resolver boundary once that source owner composes it.

## Safety

Authorization provenance narrowing only. No target interaction, scanning, exploit behavior, execution widening, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
