# Offline reference: DNS aliases and HTTP redirects do not convey consent

**Status:** proposed acceptance model, not a production gate. Synthetic `.test` names only.

## Authorization invariant

A grant for one literal host does not establish authorization for a DNS alias, CNAME destination, CDN edge, redirected hostname, sibling subdomain or suffix match. On every change of hostname identity, the production owner must either prove that *that exact identity* was approved by an authoritative current grant or deny before making any connection to the newly identified host. A redirect to an eventually approved destination cannot excuse an unapproved intermediate hop. Do not fetch a redirect destination to determine whether it is safe.

DNS-to-IP resolution and rebinding present a separate boundary: this reference does **not** authorize resolved IPs, redirects, cross-origin hops or outbound connections. Production integration must validate exact grant ownership and scope, approval freshness, capability, risk, tenant, revocation and effective resolved endpoint at dispatch/connection time; it must not infer permissions from these reference string checks.

## Offline acceptance scenarios

- Exact explicitly approved host: reference permits identity membership only; not actual execution.
- New sibling, suffix, CNAME alias, external redirect, or unapproved intermediate hop: deny.
- Every redirect and DNS alias independently present in the approved set: reference identity membership only.
- Uppercase/trailing-dot/URL/port/wildcard/non-string values: reject rather than normalize into authority.
- Empty, duplicated or malformed approval sets: reject.

Run: `python -m unittest discover -s tests -p 'test_scope_dns_redirect_authority_reference_20261008.py' -v`.

## Parallel ownership and release gate

Only this document and its isolated test are touched. Do not merge as a substitute for the production executor/authorization owners' integration and source-level negative tests. No networking, DNS lookup, asset scans, capability invocation, target interaction or deployment has been performed. Require exact-head CI and canonical permanent VPS runner verification, independent owner review and current-scope approval before claiming production enforcement.
