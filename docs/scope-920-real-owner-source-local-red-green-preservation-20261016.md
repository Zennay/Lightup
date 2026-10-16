# #920 W20 — REAL WebSecurity source-owner RED→local candidate GREEN; no production write

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This receipt is a **locally tested repair proposal**, not a production fix or permission to deploy. Source-owner [PR #202](https://github.com/Zennay/Lightup/pull/202) remains the sole owner of `src/lightup/webapp/security.py`. We did NOT edit PR #202, open a competing PR, merge, enable real authority or dispatch jobs.

## Exact trusted input provenance (GitHub content matched at byte level)

- Source-owner exact PR #202 HEAD `0a6eb118de5153eb72115cc871122175b8d54dfd`; original `src/lightup/webapp/security.py` **git blob `44b2e78c41832d87d64d4bf1f9081b04ad50d806`**.
- Original #918 source-RED suite `tests/test_scope_authorization_trusted_proxy_identity.py`, git blob `bd4049f0d3d1f7d0726cdda103238c26300d3614`.
- Original #919 source-RED suite `tests/test_scope_authorization_public_origin_identity.py`, git blob `1896265dd80b0bdee2dbb61ab31c2e7ec285b257`.
- New **only-additive** test `tests/test_scope_920_owner_source_preservation_w20.py`, git blob `636f890a093dba0297b6f4c763f48bdc121b376b`; it has 13 synthetic GET/POST/development path controls; no DNS, sockets, real targets, scans, grants or handler execution.

All four local file bytes were independently checked against their **actual GitHub git-blob SHA** (not merely file name or a documentation SHA).

## Genuine observed RED before any patch

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests \
  -p 'test_scope_authorization_*identity.py' -q
```

**Original unmodified PR #202 source: 8 tests run, 4 real FAIL**. The 4 normal controls (canonical HTTPS, HTTP rejected, loopback accepted, remote peer rejected) PASS, but both `str` subclasses in both source suites are **not rejected as required**. This is actual installed-owner source-failure evidence, **not** the previous opt-in helper's 18 green tests.

The 13 new controls were also run against original owner source: **12 PASS and 1 FAIL** (new source-level synthetic forged-proxy/remote-peer canary). Combined baseline: **21 total tests, 5 FAIL** = 4 original source REDs plus new misuse canary. They cover production HTTPS GET, client socket peer, forwarded protocol, exact Host, same-/cross-site POST, Origin/Referer policy and in-process/development loopback. Denied cases expect `RequestRejected` from actual `WebSecurity.validate`.

## Minimal candidate tested LOCALLY only — DO NOT cherry-pick automatically

Insert immediately inside the existing `if self.public_origin is not None:` of `WebSecurity.__post_init__`, **before** calling `origin` or `ip_address`:

```python
            if type(self.public_origin) is not str:
                raise ValueError("public_origin must be an exact string")
            if type(self.trusted_proxy_ip) is not str:
                raise ValueError("trusted_proxy_ip must be an exact string")
```

Why first: the original production owner checks only parseability/HTTPS/loopback, which does not establish that caller-owned `str` subclasses are canonical; their custom methods or comparisons may change perceived transport identities later. Python `type(x) is str` rejects subclasses and `__class__` impersonators **before untrusted parsing/equality**, while preserving default exact strings and both loopback literals. Tests cover current fixture paths; **other integrations are still untested**.

**Locally patched DISPOSABLE copy (not pushed as a product patch): 21/21 genuine tests PASS** = all **8 original source-REDs now truly PASS**, plus **13 additional tests PASS** under **Python 3.13.5**, warnings-as-errors on ephemeral copied modules. This is one 21-test interpreter run, not 20 extra workflows.

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS='error::ResourceWarning' \
  python -m unittest discover -s tests -p 'test_scope_*' -q
# Ran 21 tests; OK (candidate local only)
```

## Factual misuse impact in the SAME LOCAL OWNER SOURCE (no external exploit claim)

A new 13th test carries the source issue all the way through synthetic `WebSecurity.validate`: when application configuration contains a custom `str` subclass pretending to be loopback, its overridden `__ne__` permits a fabricated peer `203.0.113.17` to appear equal to that proxy. The **unmodified #202 owner source CONSTRUCTS it and ACCEPTS the synthetic request**. The four-line local candidate instead rejects the config before parsing/comparison, so the new test passes.

This is an in-memory *programmatic configuration type-confusion* demonstration, **NOT** evidence that an arbitrary external HTTP visitor can inject trusted Python configuration objects. A separate tried stateful-origin subclass was admitted by the original constructor, but the tested mismatched request remained denied; **no request bypass is claimed** for that origin case. The original #919 exact-config RED remains valid.

## Non-vacuous safeguards: destructive local mutations detected

We deliberately broke the *local candidate only* twice, without pushing either change or invoking any network:
1. Disabled the `REMOTE_ADDR` peer check. The new `test_remote_peer_does_not_gain_proxy_trust` failed as required.
2. Disabled the `HTTP_X_FORWARDED_PROTO == 'https'` check. The new `test_forwarded_http_does_not_claim_https` failed as required.

Each temporary mutation caused **exactly one targeted FAIL**, proving the new suite would flag accidental widening of those two core runtime gates. The clean local candidate was restored and **all 21 tests passed again**.

## Precise blocker owner handoff

1. **PR #202 must decide/implement/review these four lines** in its OWN runtime branch with broader webapp/source regression review. This worker did **not** alter owner code; the production security issues #918/#919 remain OPEN.
2. Add this 13-case new source-level preservation/misuse suite to the owner validation as test-only input. The four original REDs must change to real ordinary PASS on a reviewed integrated immutable HEAD.
3. Run **actual hosted Python 3.11 and 3.14 jobs and permanent registered `[self-hosted,zcloud,vps]` host `vps-bb300bba`** after runner operator [issue #1144](https://github.com/Zennay/Lightup/issues/1144) establishes online registration, labels, assignment and noncancelled exact-head runs. No claimed VPS proof in this receipt.
4. Independent security/privacy plus real client/operator consent, durable pre-I/O grant/revocation and explicit **human GO** remain release gates.

**No real grant, target, network, scan, tool handler, PR/merge or deployment authorized. HOLD.**
