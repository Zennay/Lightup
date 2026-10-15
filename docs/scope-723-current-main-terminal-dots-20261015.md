# Current-main scope terminal-dot acceptance (#723 / #724)

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is not a production policy change, grant, authorization, scan, release approval, or merge/deployment instruction.

## Why this exists

The installed `ScopePolicy.normalize_host` and policy-side explicit-host membership use `rstrip(".")`. That strips **all** trailing DNS dots, not only a single syntactic root dot. Consequently, malformed target spelling `localhost..` inherits loopback, while an allowlisted synthetic hostname with two or three ending dots can inherit explicit-host authority. It also allows malformed policy entries ending in multiple dots to match otherwise canonical targets. These are source defects; a passing suite with documented expected failures does not repair them.

The previously owned #723/#724 branch was pinned to 2026-10-07 `main`. This **separate**, current-main acceptance slice adds exactly one new test module and this new review document without changing or replacing its files, the production source owner #100, or any live executor/target-capable code.

## Implemented contract

`tests/test_scope_723_current_main_terminal_dots_20261015.py` uses actual installed `Target`, `ScopePolicy`, and `Authorization` objects from source, but all values are **fictional, in-memory fixtures**; their synthetic Authorization is not a grant or evidence of customer/operator consent.

- Nine installed-source negative tests intentionally use `@expectedFailure` to keep unfixed deny conditions clearly **RED**: target-side two/three dots, policy-side two/three dots, and `localhost` two/three dots.
- Positive controls keep single-dot DNS root spelling, canonical case folding, plain `localhost`, and denied unknown hosts working.
- Independent unittest result inspection refuses masked exceptions, skipped REDs, and accidentally successful source negatives. A separate negative mutation test deliberately raises a synthetic TypeError to demonstrate that the integrity verifier distinguishes it from the genuine source AssertionError.
- Pure in-memory tests patch socket/DNS entry points to refuse target interactions and confirm no policy/fixture mutation.


## W2: 192-case current-main root-dot / URL regression sweep (2026-10-15)

This same self-owned suite now adds **three** independent genuine installed-source **expected-RED** cases, each materializing **64** actual decisions before asserting an unsafe allow was observed:

1. **Target boundary:** 32 trailing-dot counts (2–33) × two input forms (bare hostname and HTTPS URL with synthetic path). All malformed identities must deny; the current installed `rstrip(".")` source does not.
2. **Configuration boundary:** 32 malformed declared-host trailing-dot counts × canonical and singly rooted input host. Invalid policy entries must not authorize the valid spelling.
3. **Loopback boundary:** 32 malformed `localhost` trailing-dot counts × uppercase hostname and HTTP URL forms, with `allow_private_lab=False` and no synthetic grant. Loopback shorthand must not silently mint authority.

The source is still expected RED on every one of these three aggregation tests; green CI means the **tests correctly detected an unfixed bug**, not that 192 denial assertions passed. The isolated witness inspects the exact `AssertionError("True is not false")` rather than treating arbitrary crashes as acceptable expected-RED.

Three further green controls verify untrusted missing authorization never acts as consent, different hostname identities stay disjoint, and a deliberately injected TypeError is detected as a **wrong** RED witness (not silently accepted).

**No production-policy update or live I/O**. None of these synthetic URLs is resolved or contacted. The production source owner #100 must make these negative cases ordinary passing assertions after a separately reviewed repair. Raw Python3.11/3.14 hosted integration evidence is valid **only for the immutable HEAD tested**, not for prior commits; registered permanent VPS approval is a separate gate.


## W3: current-main explicit-host identity composition (#724 / #286 / #367 / #368)

Five additional ordinary passing source tests compose previously isolated legacy contracts **without modifying their original branches**:

- **#367 configuration identity:** all seven synthetic URL-like *configured* entries (scheme, userinfo, port, path, query, fragment, network-path) must not grant the embedded host.
- **#368 configuration whitespace:** six leading/trailing whitespace policy spellings (including tab, newline, CR and nonbreaking space) must remain inert; only the target-value parsing path may use its existing surrounding-whitespace normalization.
- **#286 exact scope:** wildcard, leading-dot, parent-domain, suffix/lookalike policy entries do not authorize the concrete child host.
- **Positive compatibility:** conventional decorated *target URLs* and surrounding target whitespace still normalize to the exact explicitly declared canonical host, and the configured host's **single** terminal root dot remains valid across ordinary case differences.

This current-main composition is an independent regression **check**, not a replacement for issue #724's earlier composition branch or any closed standalone acceptance issue. Its nine original terminal-dot source REDs are still unfixed. All positive tests are pure in-memory; no real DNS, sockets, domains, claims, scans or grants. Frozen CI evidence from previous W2 heads cannot validate the expanded W3 suite.


## W4: all-dot target + empty explicit-host declaration can become false authority (#723 / #297)

There is a further installed-source interaction between unrestricted `rstrip(".")` and absent **atomic policy validation**: a syntactically malformed target consisting solely of dots is normalized to the empty string. If an equally invalid `explicit_hosts` entry contains an empty string, this can be treated as a matching authorized host by unchanged `ScopePolicy.decide`. The test includes only fictional values and a synthetic never-usable `Authorization`.

- One additional **genuine source expected-RED** test checks four dot-only bare/URL targets against an intentionally corrupt, empty policy host entry, pre-materializing all four installed-source decisions; a bypass causes the test to fail as intended and the witness requires a genuine AssertionError.
- A separate ordinary **green control** checks that without the corrupt empty allowlist entry, those syntactic target values do not acquire scope.
- This interaction is a characterization, **not a request to take over** the #297 production configuration validator or #100 source ownership. Original code and other workers' test branches are untouched.
- The correct source-owner fix must reject malformed host identities **and malformed policy entries before any public grant**; replacing `rstrip` without validating the empty target or configuration may be insufficient.

With this W4 addition, the self-owned module has **10 documented source expected-RED tests** and **16 ordinary passing control/witness tests**, including 196 separately materialized in-memory malformed target/policy probes in the three W2 matrices plus W4's four. No network or real customers. Previous W3 hosted evidence does not validate W4 until run logs show this exact commit.


## W5: separate authorization-opt-out source RED without synthetic grants (2026-10-15)

Three additional expected-RED **actual installed** `ScopePolicy.decide` methods isolate the parsing/configuration defect from the legacy fake `Authorization` test fixture. They explicitly choose `require_authorization_for_public=False` in *synthetic in-memory policy objects*, meaning **no Authorization object at all is supplied**. This is not a suggestion to disable real authorization and not an executable permit; it makes a dangerous parser/configuration identity shortcut testable even when the approval boundary is absent.

- Malformed input Target: 16 two-to-17 trailing-dot counts × bare/HTTPS form = **32 genuine decisions**.
- Malformed configured allowlist entry: 16 invalid two-to-17 trailing-dot counts × canonical/singly rooted Target = **32 genuine decisions**.
- Dot-only Target with invalid empty configured host: **4 genuine decisions**.
- A separate green control confirms that when `require_authorization_for_public=True`, even malformed matches **do not** grant a public explicit host without Authorization; that is merely a control, not evidence of trusted live consent.

These **68 additional** source calls are fully materialized before one aggregate denial assertion per RED test; independent existing witness gates require exact genuine AssertionErrors and reject masked exceptions. This makes **13 expected source REDs, 17 ordinary in-memory green tests, and 264 explicitly materialized malformed target/config decisions** for this self-owned module. Earlier hosted success does not validate the W5 commit. Never merge, issue consent, dispatch or scan based on this offline characterization.


## W6: full 264-case *actual* source no-external-I/O safety gate

A new independent **ordinary green** method replays **all 264** malformed synthetic Target/policy decisions from the W2/W4/W5 categories through the actual installed `ScopePolicy.decide` (no mock policy) while patching Python socket constructors, DNS, connection, subprocess execution, shell execution and `urllib.request.urlopen` to immediately fail any attempted network/process activity. It verifies exactly 264 decisions actually ran and their returned decision/Boolean primitive types. It does **not** assert that currently unsafe decisions are allowed, and therefore remains valid when the original source owner fixes the RED admission bug. The 264 original explicit denial requirements remain separately documented as intentionally failing source tests.

This is **not** a test against real customer infrastructure, a live network or a grant engine. Inputs are entirely fictional; neither DNS nor HTTP calls are made. The new check may detect unintended target I/O introduced by future code changes while remaining independent of the source-owner PR #100. CI must run on the new exact HEAD to validate this W6 implementation.


## W7: malformed IPv4 literal trailing-dots cross *three* authority paths (#723)

Current source `normalize_host(value)` strips an arbitrary number of root dots **before** `ip_address(...)`, so malformed input can be mistaken for a canonical IPv4 literal. A new collision-free extension of the already self-owned source acceptance module covers three distinct installed-source admission paths without changing the production owner or the parallel network/CIDR workers:

1. **Loopback:** malformed bare/HTTP `127.0.0.1..` variants must *never* inherit `LOOPBACK`; default fixture has `allow_private_lab=False` and no fake grant.
2. **Private lab:** malformed bare/HTTP `10.42.43.44..` variants must *never* inherit `PRIVATE_LAB`; the opt-in private-lab flag appears solely in an in-memory offline policy fixture, not in production.
3. **Explicit CIDR:** malformed bare/HTTP `198.51.100.23..` variants must *never* inherit `EXPLICIT_NETWORK`, even with a separately synthetic `198.51.100.0/24` declared network and deliberately fake Authorization. These TEST-NET-2 values are never contacted.

Each new source-RED test **materializes 32 decisions** (two syntactic forms × 16 trailing-dot widths 2–17), totaling **96** source decisions. The ordinary green IPv4 control preserves normal loopback, explicitly enabled private-lab scope, absence-of-grant before public CIDR, and deny-by-default behavior when lab is disabled. A further green **96-case I/O canary** executes actual installed `ScopePolicy.decide` with socket/DNS/HTTP/subprocess/shell entry points patched to throw on use. Together with W2/W4/W5/W6, there are now **360 separately materialized malformed decisions**, **16 genuine source expected-RED tests**, and **20 ordinary positive/witness tests** in the self-owned module.

**Separation from other worker work:** network CIDR *configuration typing* is owned by #292/#296, reserved-IP policy by #1422, and real dynamic consent/asset binding by production #100. W7 is strictly **source identity text parsing on the target side** within the same owned #723 root-dot bug; no CIDR parsing implementation, grants, scanner, runner, production source, or other worker files change. The source owner must reject invalid multiple terminal dots **before** any loopback, private-lab or CIDR membership decision and convert all expected-RED cases to ordinary PASS after reviewed repair. Passing hosted checks containing intentional REDs do not grant production authority.


## W8: enforce fail-closed at the *normalization* boundary, not only at admit

Earlier acceptance focuses on `ScopePolicy.decide`, which currently hides the originating malformed spelling once `normalize_host` has stripped **all** trailing dots. A future policy fix must not merely block one known caller while leaving the public normalizer capable of producing trusted canonical host identities from malformed raw text.

Three direct-source installed parser acceptance methods pin this separation:

- **Source RED #1:** **160** actual `ScopePolicy.normalize_host` invocations (five synthetically named DNS/localhost/IPv4 identities × 16 malformed widths of 2–17 trailing dots × bare and HTTP URL forms), expected to reject with `None` rather than return a canonical trusted host.
- **Source RED #2:** four dot-only malformed bare and synthetic URL values must also be rejected with `None`, not the empty normalized string.
- **Ordinary passing compatibility control:** five canonical identities remain normalized as before when bare, spelled with **exactly one** legal root dot, or embedded in a synthetic HTTP URL. Blank/whitespace-only inputs retain existing `None` behavior.

The two deliberately RED tests also flow through the independent exception witness and network-tripwire controls. **164 additionally materialized parser calls**, separate from the **360 actual `ScopePolicy.decide` malformed scenario checks**. This extends total self-owned test methods to **18 genuine source expected-REDs and 21 ordinary passing/witness methods**. It changes no production source and is not consent/asset approval or target I/O. Hosted evidence for previous commits does not prove the W8 exact HEAD.


## W9: port-qualified malformed authority identities, no transport execution

Prior W7/W8 regressions cover bare hosts and synthetic HTTP paths. W9 adds a **distinct host:port normalization boundary**: a syntactically malformed hostname or IPv4 literal ending with 2, 3, 7 or 17 trailing dots **before** a separately spelled numeric URL port must *not* become a trusted explicit-host, loopback, private-lab or exact declared-CIDR identity. It is still #723's target host-text root-dot bug, **not** #1289's general request-envelope/URL parsing owner task.

The **new actual-source intentional expected-RED** test materializes 40 distinct `ScopePolicy.decide` calls across five synthetic host identities (fictional explicitly listed DNS, `localhost`, `127.0.0.1`, opted-in synthetic `10.42.43.44` private-lab, and TEST-NET-2 `198.51.100.23` declared CIDR) × four illegal root-dot widths × two synthetic numeric ports (80 and 8443). The fake `Authorization` in the public-host/network fixtures is explicitly **not customer consent**. Any one incorrectly allowed input makes the aggregate assertion genuinely RED.

Two independent **ordinary passing controls** keep canonical port-qualified DNS/loopback scope and public-CIDR missing-consent behavior intact; the second exercises the exact same **40** installed-source decisions with socket, DNS, connection, HTTP, subprocess and shell tripwires, proving the suite does not contact the synthetic URL targets. These **40 new malformed cases** extend the previous **360** independently materialized bad `ScopePolicy.decide` cases to **400**. The **164** direct `normalize_host` parser probes remain distinct. Across the existing self-owned module there are now **19 intentional source REDs and 23 ordinary green/witness methods**. No code executing target interactions or grants was edited, and no source-owner #100 or other-worker branch is changed. Exact-head CI, permanent VPS execution and independent release approval remain separate HOLD gates.


## W10: independently reviewable fail-closed *lexical oracle* (NOT a permission engine)

Repeated source-RED aggregates can demonstrate at least one dangerous admission without showing the exact intended normalization rule. This W10 self-owned test-only change introduces two explicit **pure lexical review helpers** confined to the existing test file, not the product source:

- `_reference_terminal_root_identity` accepts only already extracted string host identity text (never a grant) and preserves **zero or exactly one** trailing DNS-root dot. Two or more trailing dots, all-dot/blank and missing host return `None`. It is case-normalizing; it never opens a socket or authorizes a target.
- `_reference_target_host` mirrors the currently installed URL-host extraction via Python `urlparse`, then applies that **strict terminal-dot-only** lexical oracle. It is explicitly **not a complete URL validation proposal**: authority parsing, scheme, username, invalid ports and alternative ingress normalization are owned by issue #1289 and its workers. Do not use this test helper as a release-time checker without separate design review.

**Green candidate-oracle proof:** 244 different malformed synthetic hosts are covered (five dummy host/localhost/IPv4 values × 16 illegal terminal-dot counts × bare/synthetic HTTP/synthetic HTTPS-with-port forms, plus four all-dot inputs) and all must lexically return `None`. Another **30 valid spelling controls** preserve canonical, upper/lower-case, 0/1 root dot and harmless syntactic host-port URL compatibility. Explicit policy-side malformed host spelling is rejected by the same *text identity* helper without interpreting policy text as a URL; this preserves separation from #367/#368 ownership.

**New genuine installed-source RED:** the exact **same 244 malformed inputs** are evaluated by the installed `ScopePolicy.normalize_host` and compared with the pure reference. A mismatch is an intentional `@expectedFailure` (`AssertionError("True is not false")`) and passes through the existing independent anti-masking and zero-DNS/socket witness gates. A future source-owner repair that makes installed normalization strictly equal to the reviewed rule must convert the RED test to an ordinary PASS, not leave it marked expected failure.

This W10 exercise is independent of the original **400** source-scope decision cases and 164 prior direct parser probes. After W10 the owned module has **20 deliberate source RED methods and 24 normal controls**. **No production patch, grant, target interaction, other worker file changes, merge or deployment**. Exact HEAD hosted producer CI and separately registered permanent VPS runner evidence remain prerequisites for any future review, not permissions.

## To validate

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_723_current_main_terminal_dots_20261015.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

Inspect raw Python 3.11 and 3.14 hosted producer/unit logs **for this exact immutable PR SHA**. Any unexpectedSuccess means the source may have changed and the REDs must be re-reviewed and converted to ordinary passing regression tests; never hide it. A permanently registered VPS runner run is a distinct unproven gate until verified on the same SHA.

## Source-owner and release conditions

Owner of `src/lightup/scope.py` (#100) must implement fail-closed parsing/configuration validation, preserve single-root-dot semantics, and convert each negative assertion to normal PASS on the installed implementation. Additional actual binding to #177 customer/operator approval, #347 grant/window/revocation before I/O, tenant, asset, capability, destination/ingress identity, independent privacy/security review, latest-main and permanent VPS proof, and explicit human release authorization are all **required separately**. Hosted test green, even if complete, confers **zero** target scope and must not trigger scan, merge, or deploy.
