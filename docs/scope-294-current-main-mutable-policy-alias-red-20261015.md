# Issue #294 — current-main mutable policy input aliasing, expected-RED

**15 October 2026 · INCUBATE M3/M7 / PLAN-LAB ONLY / DRAFT-HOLD.**

## Installed source observation

`ScopePolicy` in `src/lightup/scope.py` is a frozen dataclass, but Python does not enforce its `frozenset[str]` and `tuple[str, ...]` annotations on caller-supplied containers. A caller can supply mutable `set` or `list`, and subsequent mutations can change a previously created policy's decisions. This is an **actual open scope-integrity gap (#294)**, not an authorized grant or demonstration on a real asset.

## Independent additive current-main acceptance

`tests/test_scope_294_current_main_mutable_alias_red_20261015.py` adds **nine** real `unittest` methods and no runtime changes:

- Exactly **six** `@unittest.expectedFailure` security canaries: original host-set and network-list containers must become immutable canonical snapshots and later **additions and removals** must not widen or narrow an already-created policy.
- Three passing controls: canonical `frozenset`/`tuple` membership remains stable; a declared synthetic public host/IP requires separate authorization when not supplied; and policy decisions invoke no socket, DNS or subprocess.
- Test fixtures use `.test` host strings and fictional address literals solely as in-memory values; there is no DNS, HTTP, scan, handler, activation or real customer grant. `FICTIONAL_AUTH` is explicitly not consent.

The previous owner-created acceptance is on an untouched October 6 branch `chatgpt/scope-authorization-policy-snapshot-red-20261006`; a separate original combined #291/#294 branch has historical [registered VPS expected-RED receipt](https://github.com/Zennay/zCloud/actions/runs/37545983813) for its **own older SHA only**. Neither is proof for this new branch. This independent test keeps original branch filenames, old worker-owned docs, source and runtime separate.

## Verification and release

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_294_current_main_mutable_alias_red_20261015.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

The required evidence is *exactly six expected failures and three ordinary positive controls*, with no unexpected failures or accidental successes. An `expectedFailure` acknowledges the **original installed problem still exists** and must not be interpreted as remediation or release readiness. Source owner #100 must implement validated immutable snapshots in `scope.py` and then convert these six expected RED canaries to plain passing tests. Other source boundaries #177 consent, #347 revocation, identity, destination and ingress still need independent review, canonical registered permanent VPS proof, privacy/security and explicit human approval.

**Never merge, deploy, issue grants, scan external targets, or infer authorization from CI. DRAFT/HOLD.**
