# #291 owner-branch source acceptance: bare IPv6 must not inherit a DNS asset

**Phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT/HOLD, NO MERGE/DEPLOY/GRANTS/SCANS.**

## Parent and collision boundary
This additive child is based on the **exact unmerged source-owner #100 commit**
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`. It is **NOT** based
on the default `main` code. It does not alter any existing file, PR #100's
branch, production authorization, tokens, workflows, runner or another worker.
It exists to hand an independent source-owner reproducible regression to the
person responsible for repairing the actual product. The original owner
must independently review and intentionally select whether and how to
incorporate any acceptance evidence. Never merge into the release branch
without normal full security/privacy/authorization gates.

## Independent installed-source finding
The unmerged #100 source introduces
`Authorization.assets` and calls `allows_asset(host)` at the end of
`ScopePolicy.decide`, **after** `normalize_host`. The raw synthetic
documentation IPv6 target `2001:db8:55::beef` is truncated by the
unmodified URL parser to the entirely different DNS label `2001`.
Thus a fictional `explicit_hosts={"2001"}` and fictional
`Authorization(assets=("2001",))` can pass the new asset check even
though the full IPv6 target was never in that asset list. The existing
AUTHORIZED-mode ActivationGate may then create an in-memory fake
ExecutionPermit with the short host as its identity.

The fix must **parse the original target exactly first**, using the
complete canonical IPv6 literal or rejecting it as an invalid target,
*before* explicit-host membership, `allows_asset`, temporal/revocation
checks, or token issuance.

## Implemented targeted tests
Only one new test module and this documentation:
`tests/test_scope_291_pr100_asset_identity_boundary_20261015.py`

- Four **real expected-RED** cases on unmerged #100 source: wrong
  explicit-host+asset acceptance, synthetic ActivationGate permit for the
  wrong address, and 128 distinct RFC3849 wrong-asset admissions.
- Ten regular green comparators and integrity guards: an asset
  containing the **correct** full IPv6 does **not** satisfy the
  unrelated DNS alias, empty assets grant nothing, bracketed IPv6
  `/128` with matching exact asset retains target/authorization
  provenance, mismatched exact CIDR asset cannot mint token, revoked
  and expired claims cannot mint tokens, socket and DNS trips are active,
  and expected REDs are witnessed as actual AssertionErrors with known
  messages rather than runtime crashes or unexpected success.
- All input IPs are RFC3849 documentation-only; fictitious token values
  and fictional authorization actors have **no real customer authority**.
  `socket.socket`, `socket.create_connection` and
  `socket.getaddrinfo` are patched to raise. No adapters, HTTP,
  scans, persistence or actual target interactions.

Run on a separate checkout of the specifically pinned owner branch:

```sh
PYTHONPATH=src python -m unittest -v \
  tests.test_scope_291_pr100_asset_identity_boundary_20261015
```

`@unittest.expectedFailure` is an **expected source defect**, not a
test of corrected security. After the original owner repairs the
production parser, all four source REDs must become ordinary passing
tests. The exact-head hosted job and separate permanently registered
VPS runner must independently complete; parent main may have unrelated
CI failures. Hosted success is never proof of registered VPS execution
or customer consent.

## Explicit limitations
This child branch does not contain the separate current-main tests from
[draft PR #1448](https://github.com/Zennay/Lightup/pull/1448).
It does not prove deployment readiness, source-owner signoff or actual
asset ownership. Related issues #1289, #1422, #177 and pre-I/O
revocation remain independent release gates.

## W2: installed #100 permit boundary at scale

This tests-only branch now also proves the **real proposed ActivationGate**
can generate a synthetic in-memory execution-permit token for each of **128
different bare RFC3849 IPv6 targets**, while the sole fictional allowed
asset is the unrelated DNS alias `"2001"`. The token generator is patched
to return only `FAKE-NEVER-LIVE`; every call is counted, no secret or real
client token is created. This is a fourth genuine installed-source
expected-RED test, guarded by the independent assertion witness.

An additional ordinary-green matrix sends the same **128 identities in
bracketed IPv6 form** through an exact `/120` network scope, paired with
the **incorrect** claimed DNS asset. In all cases the actual source-owned
ScopePolicy must return `AUTHORIZATION_ASSET_MISMATCH`, and the actual
ActivationGate must reject before the fake token function is touched.
This distinguishes a lexical alias from the correct independent asset
gate. All paths are in-memory, without sockets, real permissions or
adapter execution.

Total own module: **4 expected-RED and 10 normal PASS/witness methods**.
Separate current-main PR #1448 remains unchanged. The original #100
source branch is *not* modified.

## W3: synthetic source-fix negative control

An independent passing acceptance method temporarily patches only the
**in-memory test process** to reject bare IPv6 literals as invalid
**before scope membership**. It then reruns each of the four real
`@unittest.expectedFailure` source tests and insists that each becomes
an **unexpected success**, not an ignored failure or a runtime crash.
This proves a safe source fix actually retires the RED signals and
cannot leave deceptive "expected failure" green dashboards behind.
The same temporary denial keeps an exact bracketed IPv6 `/128`
positive permit green, so the simulation does not erase all legitimate
scope membership. The original `ScopePolicy` is restored after
the test; no deployed source is modified.

The in-memory denial is **only a test of the test**, not a candidate
production parser replacement or real authorization.
