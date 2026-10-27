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

## W40 — avoid treating any zero-IID ULA /64 candidate as a verified host
A previous outer-block-only guard refused `fc00::` but still marked `fd00::` and `fcaa:1234:5678:9abc::` `REVIEW_ONLY`. Each has a 64-bit all-zero interface identifier. In IPv6 subnets such an address can represent the reserved **subnet-router anycast** identifier rather than an ordinary individually verified host, and an IP literal without a trusted prefix/tenant route cannot distinguish host assignment.

The standalone reviewer therefore conservatively returns `HOLD` for **every ULA address with a zero final 64-bit interface identifier**, not merely `fc00::`. Neighboring nonzero IID literals remain advisory `REVIEW_ONLY` — not a real grant. The independent deterministic integer oracle now encodes the same membership contract without `is_private` or `is_global`. New `tests/test_scope_lab_ula_zero_interface_1424.py` verifies explicit `fc00`/`fd00` examples, 96 seeded unrelated ULA /64 prefixes, atomic-batch HOLD if one candidate has zero IID, and the actual single/batch CLIs' false-only JSON with strictly nonzero exit codes.

**Safety limitation:** all-zero IID is not necessarily unusable on every real network, and nonzero IID does not prove a host actually exists. This is purposely conservative, non-authorizing offline triage; only the installed grant/tenant/scope/risk/revocation review owners can make operational authorization decisions.

## W41 — strict single-CLI argument types and fail-closed review output
The opt-in single-literal entrypoint now checks the **exact built-in `list`** argument container and **exact built-in `str`** type for both `--literal` and its value before performing any string equality or literal classification. A malicious list/string subclass or object with custom `__len__`/`__eq__` hooks must not cause side effects, get coerced into scope or crash a supposedly safe offline reviewer. Invalid inputs produce fixed HOLD output only.

Both the single-literal and the atomic-batch review CLIs catch `OSError` (including broken pipes) and `UnicodeError` when the output sink cannot accept their privacy-minimal JSON. They return **exit 2 (HOLD)** without logging exception details; a normal review-only result remains exit 3, never 0. Since a failed sink could have written only part of an output buffer, **a consumer MUST require a complete parseable receipt and MUST NEVER treat partial or missing output as authorization**. Any receipt remains non-authorizing regardless of exit code.

`tests/test_scope_lab_cli_sink_1424_offline.py` covers hostile direct-call flags before getter/equality hooks, genuine output and privacy-positive controls, and both CLIs under synthetic `BrokenPipeError`, `OSError`, and `UnicodeEncodeError` sinks. These are self-contained Python in-memory tests only, without actual files, networks, targets or active scans.
