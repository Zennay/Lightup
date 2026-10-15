# Source-owner acceptance: explicit network identity (#292 / #296)

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This change is a standalone, add-only test contract from current `main`. It does not edit `src/lightup/scope.py`, PR #100 or #164, execution, runner workflows, permissions, or customer data.

## Current installed vulnerabilities (not fixed by these tests)

- **#292**: `ip_network(134744072)`, four IPv4 bytes, `True`, and a `str` subclass are accepted as network definitions despite an annotated `tuple[str, ...]`. Mis-typed configuration can therefore acquire the authority of an explicit network.
- **#296**: `ip_network("8.8.8.8/24", strict=False)` becomes `8.8.8.0/24`. A different public IP in the expanded subnet can then be treated as allowed. IPv6 has the same host-bit widening defect. Additionally, `ip_network()` accepts bare host strings as implicit `/32` or `/128`, dotted IPv4 netmasks as a `/prefix`, and long-form IPv6 notation instead of strict canonical CIDRs. Under this issue's explicit canonical declaration contract these must be rejected before admission. The most dangerous source-level widening is a host-bearing `/0` typo: `8.8.8.8/0` silently becomes `0.0.0.0/0` and `2001:4860:4860::8888/0` becomes `::/0`, potentially selecting an entire public address family with synthetic grant metadata. Both are now isolated expected-RED canaries, never network requests.
- **The installed behavior and the tests are never a customer grant.** Their `Authorization` instance is a synthetic in-memory fixture. No sockets, DNS, shell command, production API, targets, scan, or grants are invoked.

## Implemented executable acceptance

`tests/test_scope_292_296_current_main_source_red_20261015.py` asserts that malformed declarations either fail to construct/evaluate or return `allowed=False`. Eighteen deliberately `@expectedFailure` canaries demonstrate eighteen real fail-open cases on installed `main`, including stdlib IPv4Address/IPv4Network/IPv6Address/IPv6Network instances, host-bit CIDR widening, bare public IPv4/IPv6 addresses accepted as implicit /32 or /128, dotted IPv4 masks and non-canonical expanded IPv6 notation; a separate witness executes all eighteen and requires **eighteen real AssertionError failures**, not a masked parser exception or unexpected success. Positive controls preserve canonical IPv4 `/24`, IPv4 `/32`, IPv6 `/64` and IPv6 `/128` semantics, and confirm missing synthetic authorization denies public network membership. Negative controls test bytearray, None, nonsense strings and no-network/no-process tripwires.

## Current-main review additions — strict canonical oracle + falsification

The new **test-only** `_strict_canonical_declaration` predicate is a reproducible
syntax oracle, *not* an installed grant decision. It rejects non-exact Python
`str` objects, missing prefix slashes, space-padded values, host bits,
dotted-netmask aliases, expanded IPv6 spellings and other non-canonical text.
It uses `ip_network(..., strict=True)` and exact round-trip equality to the
canonical string. Canonical `0.0.0.0/0` or `::/0` are syntactically
valid **but do not imply permission**: asset ownership, customer/operator
provenance, target binding, revocation and human review remain independent.

The oracle has a negative/positive matrix and **256 deterministic synthetic
single-host round trips** (128 IPv4 + 128 IPv6). It also rejects their
slash-free spellings so an implicit host-sized prefix cannot silently enter
scope. This does not authorize the example network addresses or query DNS.

Four additional *mutation controls* deliberately simulate an incorrect
producer: a masked parser `TypeError`, an unexpected all-green
`@expectedFailure`, a forged unrelated `AssertionError` and a missing
replay case. The witness must reject each false proof. Original 18 installed
source RED cases still require exactly 18 genuine `AssertionError` results
and no network/process I/O. All mutation controls use disposable in-memory
`unittest.TestResult` objects and alter no production file.

## Owner implementation checklist (not applied to installed source)

1. Validate the **whole** explicit-network configuration before any permission decision, rather than filtering invalid values and keeping the others; issue #297 independently owns broader policy atomicity.
2. On each original value check `type(value) is str`, non-empty, no surrounding whitespace, an explicit slash prefix, and that `ip_network(value, strict=True)` parses it without widening. For the canonical-display contract require the input to match the canonical `str(network)` exactly. A valid single host must use explicit `/32` or `/128`.
3. Do not accept numeric, byte-like, standard-library IP/network objects, `str` subclasses, dotted-mask aliases, expanded IPv6 spellings, or host-bit-bearing declarations as policy authority. Do not silently normalize and grant on the broader CIDR.
4. Keep scope/authorization decisions deny-by-default on bad configuration and preserve the caller's explicit canonical CIDRs. Coordinate with #294's snapshot owner so validation is never bypassed by later caller mutation; maintain the independent #177/#347 live gates.
5. Replace each `expectedFailure` with normal passing tests **only after** the source fix. The companion witness deliberately asserts the current failures and must be switched to strict green semantics in the same owner-controlled integration, preventing intentional REDs being mistaken for release proof.

**Isolation assurance:** The replay witness forbids sockets, DNS, subprocesses and shell calls for all eighteen synthetic RED fixtures. No customer asset or runtime code is involved.

## Conditions before owner integration or closing issues

1. Original source owner updates only their production-owned `ScopePolicy`: exact built-in nonempty string entries, strict canonical network declarations and no implicit host-bit widening. Choose fail-closed handling that cannot mint a permit.
2. Convert all eighteen `@expectedFailure` cases to normal passing assertions **after** original source fix. The witness must then be revised to require eighteen ordinary successes, not simply deleted; leaving `unexpectedSuccess` is correctly a failed gate.
3. Complete exact-commit CI on both supported Python versions, and independently verify self-hosted **permanently registered** VPS evidence. A queued job, hosted preflight or branch-local unittest is not proof of permanent VPS execution.
4. Preserve actual `#177` verified assessment/customer/operator consent, `#347` live revocation before any I/O, tenant/asset/capability/destination/ingress binding, security/privacy review and explicit human approval. These cannot be inferred from this test suite.
5. Keep this PR **DRAFT/HOLD**. No merge, production deployment, grants, real-target discovery or scans.

Tracking: [#292](https://github.com/Zennay/Lightup/issues/292), [#296](https://github.com/Zennay/Lightup/issues/296), [source-owner #100](https://github.com/Zennay/Lightup/pull/100).
