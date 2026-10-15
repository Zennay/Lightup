# Source-owner acceptance: explicit network identity (#292 / #296)

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This change is a standalone, add-only test contract from current `main`. It does not edit `src/lightup/scope.py`, PR #100 or #164, execution, runner workflows, permissions, or customer data.

## Current installed vulnerabilities (not fixed by these tests)

- **#292**: `ip_network(134744072)`, four IPv4 bytes, `True`, and a `str` subclass are accepted as network definitions despite an annotated `tuple[str, ...]`. Mis-typed configuration can therefore acquire the authority of an explicit network.
- **#296**: `ip_network("8.8.8.8/24", strict=False)` becomes `8.8.8.0/24`. A different public IP in the expanded subnet can then be treated as allowed. IPv6 has the same host-bit widening defect.
- **The installed behavior and the tests are never a customer grant.** Their `Authorization` instance is a synthetic in-memory fixture. No sockets, DNS, shell command, production API, targets, scan, or grants are invoked.

## Implemented executable acceptance

`tests/test_scope_292_296_current_main_source_red_20261015.py` asserts that malformed declarations either fail to construct/evaluate or return `allowed=False`. Ten deliberately `@expectedFailure` canaries demonstrate the ten actual fail-open cases on installed `main`, including stdlib IPv4Address, IPv4Network, IPv6Address instances and host-bit dotted-mask notation; a separate witness executes all ten and requires **ten real AssertionError failures**, not a masked parser exception or unexpected success. Positive controls preserve canonical IPv4 `/24`, IPv4 `/32` and IPv6 `/128` semantics, and confirm missing synthetic authorization denies public network membership. Negative controls test bytearray, None, nonsense strings and no-network/no-process tripwires.

## Conditions before owner integration or closing issues

1. Original source owner updates only their production-owned `ScopePolicy`: exact built-in nonempty string entries, strict canonical network declarations and no implicit host-bit widening. Choose fail-closed handling that cannot mint a permit.
2. Convert all ten `@expectedFailure` cases to normal passing assertions **after** original source fix. The witness must then be revised to require ten ordinary successes, not simply deleted; leaving `unexpectedSuccess` is correctly a failed gate.
3. Complete exact-commit CI on both supported Python versions, and independently verify self-hosted **permanently registered** VPS evidence. A queued job, hosted preflight or branch-local unittest is not proof of permanent VPS execution.
4. Preserve actual `#177` verified assessment/customer/operator consent, `#347` live revocation before any I/O, tenant/asset/capability/destination/ingress binding, security/privacy review and explicit human approval. These cannot be inferred from this test suite.
5. Keep this PR **DRAFT/HOLD**. No merge, production deployment, grants, real-target discovery or scans.

Tracking: [#292](https://github.com/Zennay/Lightup/issues/292), [#296](https://github.com/Zennay/Lightup/issues/296), [source-owner #100](https://github.com/Zennay/Lightup/pull/100).
