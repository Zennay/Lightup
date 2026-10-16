# LightUp #920 — combined production WebSecurity trust-identity acceptance

**State: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO RELEASE.**
This branch is an **isolated, non-authorizing composition** of the existing
test/doc sidecars for #918 and #919; the original production source owner
[PR #202](https://github.com/Zennay/Lightup/pull/202) retains exclusive
ownership of `src/lightup/webapp/security.py`.

## Exact immutable ancestry and source manifest

- Base: PR #202 head `0a6eb118de5153eb72115cc871122175b8d54dfd`
  (not current main, intentionally pinned to the source implementation under review).
- Copied **byte-identically**, not cherry-picked into, rebased over or modified on
  either source-worker branch:
  - `tests/test_scope_918_canonical_proxy_identity_20261012.py`
    from draft PR #1256, HEAD `f6529ceb82e5f655994ce63c0e475e20b3bfb36a`,
    source blob `475367364d3aaa72dac0890ee329bfdb180eac87`.
  - `docs/scope-918-canonical-trusted-proxy-identity-20261012.md`
    from PR #1256, blob `fe97edc43daa20a7db7c9c27b85172c3566ad606`.
  - `tests/test_scope_919_public_origin_identity_20261012.py`
    from draft PR #1255, HEAD `f1e20ff8651358da4666a0844191160e82e02738`,
    source blob `0387081a4f622ba32dd708f5b5ce43eec7c9137b`.
  - `docs/scope-919-canonical-public-origin-identity-20261012.md`
    from PR #1255, blob `4ecfd473b2a22e1413bead968b420b13b58bf80a`.
- Fifth new file: `tests/test_scope_920_transport_identity_composition_20261016.py`,
  seven additional **ordinary fail-closed controls** exercising BOTH exact
  production-mode ingress predicates against fictional `.example.test` host
  and documentation-only `203.0.113.77` peer. No sockets or outbound calls.
- Sixth new file: this manifest. All paths are new on PR #202 base. No
  existing production, worker-owned test, workflow, CI, deployment or runner
  file is modified.

## Required correctness and existing source REDs

#918 requires `type(trusted_proxy_ip) is str` and an actual loopback address
**before** admitting production proxy trust. A user-defined `str` subclass
must never control peer equality.

#919 requires `type(public_origin) is str` for non-null production config,
a stable immutable canonical origin, and no polymorphic `str` methods affecting
parsing after constructor validation.

Both sidecar test modules deliberately contain **two `expectedFailure` source
contracts each**. They are evidence of unresolved source issues, not success.
The new composition tests are green controls only and **cannot fix or certify**
the two source flaws. An unexpectedSuccess, ordinary FAIL or ERROR is not a
release success and must be investigated; do not silently suppress it.

For a valid future release, #202's owner must implement constructor-time exact
identity checks, preserve both predicates through request handling, and make
the four source REDs ordinary passing tests. Validate compatibility with the
latest shared base, actual ingress/TLS, operator/client consent, tenant/session
boundaries, revocation, independently authenticated proxy/network identity,
registered permanent VPS runner and human security/privacy review.

## Non-authorizing verification guidance

After an exact-head checkout in a controlled runner:

```sh
for file in \
  test_scope_918_canonical_proxy_identity_20261012.py \
  test_scope_919_public_origin_identity_20261012.py \
  test_scope_920_transport_identity_composition_20261016.py; do
  PYTHONPATH=src python -m unittest discover -s tests -p "$file" -v || exit 1
done
```

Capture the precise commit SHA, Python 3.11/3.14 results and each
`expectedFailure`, plus genuine registered permanent VPS provenance before
claiming tested. The composition **does not** imply those checks have run.
To avoid worsening the existing permanent self-hosted CI backlog, keep
branch-only and do not initiate a duplicate canonical CI run or merge/deploy
without owner coordination.

All inputs are fictional in-process HTTP metadata. No real request to a
customer, active scan, privilege grant, tool dispatch, model execution,
external listener, deployment, release approval or trusted release artifact
is created. **DRAFT/HOLD**.
