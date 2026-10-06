# URL authority scope-authorization contract

Issue: #267

LightUp treats the parsed destination host as the only URL component that can
satisfy host scope. Display-adjacent text is not authority.

This tests/docs-only contract freezes the following fail-closed behavior:

- an explicit port, path, query or fragment does not change the canonical host;
- an allowlisted hostname placed in URL userinfo cannot authorize the actual
  destination host;
- the same userinfo rule applies to schemeless target input;
- an allowlisted hostname appearing only in query or fragment data is ignored
  for scope;
- parent-suffix and subdomain lookalikes are not implicitly included by an exact
  host allowlist;
- percent-encoded display/userinfo text cannot replace the parsed destination
  authority;
- URL userinfo containing `localhost`, a loopback IP or a private IP cannot
  grant loopback/private-lab trust to the real destination authority;
- DNS names that merely contain `localhost` or loopback-looking text are not
  treated as loopback.

The regression module exercises only `ScopePolicy.decide` with in-memory
`Target` objects. It performs no DNS lookup, socket connection, HTTP request,
tool execution, scanning, target interaction, remediation/retest, deployment,
or authorization widening.

## Collision boundary

This slice intentionally adds only:

- `tests/test_scope_authorization_url_authority_contract.py`
- `docs/scope-authorization-url-authority-contract.md`

It does not modify production scope, activation, execution-policy, domain,
planner, worker or evidence-remediation code, and it does not touch the
dedicated files owned by the active public-gate defense-in-depth PR.

## Promotion gate

The branch remains branch-only while canonical self-hosted LightUp CI is
stalled. A draft PR should be opened only when it will not amplify the runner
queue, followed by exact-head hosted diagnostics and canonical VPS proof before
promotion.
