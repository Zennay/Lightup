# LightUp #920 — offline WebSecurity transport identity composition

**LightUp Incubate M3/M7 — PLAN/LAB ONLY. BRANCH-ONLY / EXPECTED RED / HOLD / NO MERGE / NO DEPLOY.**

## Original ownership and immutable inputs

- Sole production owner: [DRAFT PR #202](https://github.com/Zennay/Lightup/pull/202) on `src/lightup/webapp/security.py` at exact owner HEAD `0a6eb118de5153eb72115cc871122175b8d54dfd`. This pack makes **zero production edits**.
- [Issue #918](https://github.com/Zennay/Lightup/issues/918) original branch `chatgpt/scope-authorization-trusted-proxy-identity-red-20261007`: keep `tests/test_scope_authorization_trusted_proxy_identity.py` (blob `bd4049f0d3d1f7d0726cdda103238c26300d3614`) and `docs/scope-authorization-trusted-proxy-identity.md` (blob `bc9d17acaf4394c1eddc09992cab10d8740f098c`) byte-for-byte.
- [Issue #919](https://github.com/Zennay/Lightup/issues/919) original branch `chatgpt/scope-authorization-public-origin-identity-red-20261007`: copy `tests/test_scope_authorization_public_origin_identity.py` (blob `1896265dd80b0bdee2dbb61ab31c2e7ec285b257`) and `docs/scope-authorization-public-origin-identity.md` (blob `751d7bb042a102589cd13512e96e21f5af478c65`) byte-for-byte.
- This separate **#920 integration branch** starts atop #918's exact original branch and imports the two unchanged #919 files. Do not modify parent branches or concurrent workers. Dedicated combination coverage is optional and must be new-path-only.

## Required security outcomes

1. Reject any production `trusted_proxy_ip` whose exact type is not `str` **before** accepting configuration or comparing it with `REMOTE_ADDR`. A `str` subclass may overrule equality and spoof a remote peer.
2. Reject a non-`None` production `public_origin` whose exact type is not `str` **before** parsing. A mutable `str` subclass may change how URL parsing behaves between construction and requests.
3. Canonical exact IPv4/IPv6 loopback proxy and HTTPS origin inputs must continue working; actual remote peer mismatches and cross-origin requests must still fail closed.
4. Check the combined invalid-input path **without network activity**. Never infer that the source is repaired from an expected-RED test.

## Reproduction and expected results

Run under the *pinned branch checkout* (not against current main):

    PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_scope_authorization_*identity.py' -v
    PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_scope_920_transport_identity_composition_20261012.py' -v

The two original regression modules each have two canonical controls and two deliberately **unannotated RED** failures against the current PR #202 security source. These are intentionally retained as true failing test assertions. The new composition module may use an isolated `expectedFailure` canary to document combined behavior. Until the original source owner fixes the cause, ordinary complete CI on this branch is expected RED, not a release pass.

## Mechanical composition provenance (additive, review-only)

`tests/test_scope_920_composition_provenance_20261012.py` pins the five original Git blob IDs: unchanged #202 production `security.py` and the untouched #918/#919 regression and documentation inputs. It catches accidental source-owner edits or textual rewrites during composition. This is a *review provenance guard*, not runtime trust, release proof, a cryptographic grant or permission to execute. Intentionally restacking on a genuine owner fix requires explicit checksum updates and a full source review; never silently relax this test.

    PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_scope_920_composition_provenance_20261012.py' -v

## Gating / non-collision

- Keep branch-only while canonical self-hosted CI is congested; don't create duplicate canonical queue slots or a premature PR solely to run expected-RED tests.
- Source-owner #202 absorbs the actual exact-type guards; only then change original RED tests to ordinary green, restack on latest-main, and run exact-head Python 3.11/3.14 hosted preflight + separately registered permanent `vps-bb300bba` CI.
- Independent privacy/security/tenant and production ingress (Nginx, trusted proxy, Host, Origin) review and explicit human release approval remain mandatory. No real request listener, target, assessment, scanning, grant, capability, remediation or deployment.
