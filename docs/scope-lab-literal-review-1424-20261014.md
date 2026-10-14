# #1424 — opt-in exact lab IP-literal reviewer (non-authorizing)

**LightUp stays INCUBATE M3/M7 · PLAN/LAB ONLY.** This is an independent, optional reference module. It is **NOT** installed as an authorization gate, a production scope fix, proof of customer permission, a lab scanner, a release gate, or a target-active control.

## Purpose
The current `ScopePolicy.decide()` uses `ipaddress.is_private or is_link_local` for default lab membership. Python's `is_private` includes many non-globally-routable classes outside RFC1918 and IPv6 ULA, including documentation, benchmark and unspecified destinations. [#1422](https://github.com/Zennay/Lightup/issues/1422) separately proves this bug with genuine expected-RED canaries. [Source-owner PR #100](https://github.com/Zennay/Lightup/pull/100) owns any modification to the installed `scope.py`; do not make this reference output authoritative merely by importing it.

## Concrete implementation
- `src/lightup/scope_lab_literal_review_1424.py` exposes only `review_lab_literal(value: object)`, returning a frozen/slotted `LabLiteralReview` with two display states: `HOLD` (default) or `REVIEW_ONLY`. A preview is **not** permission.
- Accepts **only exact built-in strings** with a single canonical literal. Invalid/case-varying/space-prefixed hosts, alternate dotted numeric aliases, zones, percent-encoding, IPv4-mapped IPv6, URLs, bracketed host authorities, CIDR strings, subclasses, objects and oversized input yield `HOLD`.
- Independently checks only IPv4 loopback 127/8, IPv4 RFC1918 10/8, 172.16/12, 192.168/16, IPv6 loopback `::1`, and IPv6 unique-local `fc00::/7`. Does **not** use `is_private` or `is_global` for trusted-membership.
- Crucially every result carries **exact False** for `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`. Unrecognized literals produce a fixed, privacy-minimal `HOLD` without input echoes.
- Every HOLD produces a **new isolated immutable receipt**, avoiding cross-call identity contamination even when arbitrary Python code bypasses dataclass frozen and mutates an earlier returned object. The test proves later HOLD keeps every flag false. This still is **not** a kernel, process or cryptographic isolation boundary.
- The frozen/slotted receipt's **public constructor is also runtime-validated**: no external caller can instantiate misleading truthy, integer-zero, string, `None`, or otherwise non-boolean flag values, nor combine `REVIEW_ONLY` with `UNTRUSTED` or `HOLD` with trusted classification. This guards against dataclass annotation/type confusion; it is **not** a cryptographic trust boundary and does not issue an authorization token.

## Runnable bounded offline CLI (still NO authority)
`scripts/review_scope_lab_literal_1424_offline.py` is an explicit, optional operator-facing wrapper with exactly one `--literal <canonical-address>` argument. It emits a single **constant-shape JSON** result containing only review status/classification and five exact false flags. Any missing/duplicate/invalid argument returns HOLD without reflecting the input or printing error details. Stdin is ignored; no file of customer addresses is accepted. **There is deliberately no successful zero exit code:** code 2 means HOLD and code 3 means REVIEW_ONLY; neither represents scan consent, an ExecutionPermit or a release.

```bash
python scripts/review_scope_lab_literal_1424_offline.py --literal 10.2.3.4  # REVIEW_ONLY, exit 3; no permit
python scripts/review_scope_lab_literal_1424_offline.py --literal 192.0.2.1  # HOLD, exit 2
```

## Test and release controls
`tests/test_scope_lab_literal_review_1424.py` checks positive RFC1918/ULA/loopback controls, negative IANA special-purpose cases, aliases and embedded authority strings, exact type guards (untrusted `__str__` not called), immutable false-only result flags, and patched no-DNS/no-socket/no-disk/no-process runtime.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_lab_literal_review_1424.py' -v
```

Run this on Python 3.11 and 3.14 **at the exact PR head**, plus the full suite and producer integration. Hosted proof and permanent registered VPS proof are separate requirements. Do **not** deploy or merge into production until source-owner and security reviews explicitly approve integration with the complete grant/tenant/scope/risk/revocation checks.

## Ownership
Four entirely new, self-contained paths (optional module, CLI, tests and handoff doc). Does not touch original `scope.py`, `activation.py`, tool executor, target parser [#1289](https://github.com/Zennay/Lightup/issues/1289), tenant CIDR [PR #1318](https://github.com/Zennay/Lightup/pull/1318), original [#1423](https://github.com/Zennay/Lightup/pull/1423) RED acceptance paths, any other worker, workflows, self-hosted runners, customer state, evidence or deployment.

## W39 — conservative outer-network endpoint handling and independent integer oracle
The single-literal reference now returns **HOLD** for the ambiguous *outer aggregate* network and directed-broadcast endpoints of 127/8, 10/8, 172.16/12 and 192.168/16; also for IPv6 ULA's all-zero `fc00::` network base. Neighboring ordinary literal candidates remain `REVIEW_ONLY`. This is intentionally more conservative than `ipaddress.is_private`, and **does not determine whether arbitrary CIDR-specific network or broadcast endpoints can be assigned**; only a separate reviewed network mask and actual authorization could do so.

Two targeted tests cover the exact boundary and neighboring literals, and batch acceptance proves even one edge literal changes the entire list to HOLD. A separate `tests/test_scope_lab_literal_integer_oracle_1424.py` adds reproducible weighted IPv4/IPv6 samples at all key ranges using integer range math independent of `is_private` / `is_global`. It reasserts five literally false authority flags for every accepted or denied candidate on Python 3.11/3.14. All inputs are synthetic addresses interpreted in memory only, not contacted.
