# #920 W19 — eliminate redundant IP parsing after exact synthetic loopback admission

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No installed WebSecurity change.**

## Ownership and rationale

This private tests/docs-only child is pinned to the unchanged, independently locally tested #920 W18 branch HEAD `4cd47dd3858d89cc363399c65d1cdf7dfdf637f9`. The canonical synthetic offline review tool already requires `type(proxy) is str` then **exactly one of `127.0.0.1` or `::1`**. The previous further `ipaddress.ip_address(proxy).is_loopback` could not narrow these two fixed literal strings, introducing unnecessary parser branches and an extra import. W19 removes the redundant stdlib parser entirely while preserving the exact loopback allowlist and every HOLD/REVIEW_ONLY/false-grant-flag invariant. The real transport source remains owned solely by production PR #202.

## Added hostile origin regression

One new `unittest` method with six independent `subTest` cases denies malformed IPv6 brackets, labels with leading/trailing hyphens, case-normalized spoofing, duplicate labels and invalid origin port grammar. It invokes only the synthetic in-memory helper. It neither DNS-resolves nor opens a network socket. No actual client or allowed scope is tested.

## Executed locally against GitHub-identical blobs

Python **3.13.5** in an isolated ephemeral test directory. Code and test local git-blob SHAs were independently verified against committed GitHub files:

- review helper: `b16469b232b698a24c8f547ffb6a16a0e388f644`;
- regression module: `f60424f30cf1080db82b983ec654fa64fc92efa1`.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS='error::ResourceWarning' \
  python -m unittest discover -s . -p 'test_scope_*.py' -q
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS='error::ResourceWarning' \
  pytest -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS='error::ResourceWarning' \
  coverage run --branch -m pytest -q -p no:cacheprovider
coverage report -m --include='*/scope_*_offline_*guard.py'
```

Actual W19 standalone results: **18/18 unit tests PASS, 18/18 pytest methods PASS, 47/47 subtests PASS**. Combined three isolated reference modules (#896/#897/#920) after this change: **46/46 unittest PASS, 46/46 pytest PASS, 107/107 subtests PASS**. Coverage on the three *offline helper modules only* (not LightUp): **94% total**, with W19 transport module **93%**. These are duplicate runs of the same method suite, not 92 distinct tests.

## Mutation oracle and remaining HOLD gates

The preceding W17 source-matched 5 intentional adversarial local mutations, done on disposable non-GitHub copies, were all caught by their targeted regressions; no production mutation occurred. W19 removes provably redundant IP parsing; legitimate fictional loopback still REVIEW_ONLY and remote/noncanonical peer remains HOLD.

No canonical hosted Python 3.11/3.14 job or registered VPS runner performed this W19 verification; #1144 runner queue issue remains outside this child, cause unknown. PR #202 must fix the original #918/#919 installed source-RED requirements and validate them on exact integrated source. No real consent/grants/dispatch/targets/scans/deploy; independent privacy/security and explicit human GO still absent. **Keep branch-only; no PR/merge/CI dispatch, release or actual scope grant.**