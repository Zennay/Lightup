# Scope issue #291 — bare IPv6 identity source regression (2026-10-15)

**State:** INCUBATE M3/M7 · **DRAFT/HOLD**. This branch is a
non-authorizing, tests-and-documentation-only acceptance for the unmerged
production owner. It does not authorize, deploy, scan or issue grants.

## Why this matters

The current installed `ScopePolicy.normalize_host()` passes a bare IPv6
literal to `urlparse("//" + value)`. For example, synthetic
`2001:db8:1::1111` becomes normalized host `2001`, **not** the
literal. A policy explicitly admitting the unrelated DNS label `2001`
can then return `EXPLICIT_HOST` for the IPv6 target. An attached
`Authorization(owner=..., reference=...)` does not cure this lexical
identity substitution. These are *in-memory hypothetical inputs*, not
permission to test the displayed addresses.

## Exact source acceptance

New file `tests/test_scope_291_bare_ipv6_truncation_current_main_20261015.py`:

- Nine **real expected-RED** cases prove bare IPv6 must never turn into
  a shortened name, that a synthetic explicit-host allowlist cannot
  admit the mismatched IPv6 literal, a fabricated authorization
  claim on the wrong identity, and the **real ActivationGate** handing out a
  synthetic in-memory execution permit for that falsely matched identity.
- Ten **normal green/witness controls** prove bracketed IPv6 remains intact,
  explicit `/128` network membership still requires an authorization
  object under the existing canonical flow, and the same literal in
  bracketed form cannot accidentally match an unrelated host or network. A
  PLAN_ONLY/LAB_ONLY comparators still reject the fake active request; a
  standalone network-tripwire self-test proves DNS/socket monkeypatches really
  reject calls. A RED-integrity witness reruns the nine intentional failures
  and rejects masked crashes, accidental success and network-trigger errors.
- All tests are pure in-process: actual DNS lookups, sockets and outbound
  connections are patched to raise immediately. No real network
  assessment or other active operation is performed.

A source-owner fix may **either** parse a bare literal to its complete
canonical address **or** explicitly reject it as `INVALID_TARGET`.
A truncated hextet must never become an authorized DNS-host identity.

Run in an isolated repository checkout:

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_scope_291_bare_ipv6_truncation_current_main_20261015
```

**Important:** `unittest.expectedFailure` is a red-signal quarantine,
not a successful security fix. The nine source-negative cases must
report exactly as **expected failures**, not ordinary passing tests or
unexpected successes. The owner must repair the installed source and
convert these cases to normal green tests before considering this
specific issue resolved.

## Ownership and release boundaries

- No edits to `src/lightup/scope.py`, production admission, planners,
  orchestrators, other source-owner branches, workflows or runner.
- Issue [#291](https://github.com/Zennay/Lightup/issues/291) remains
  **open** pending the separate production owner; do not merge this
  branch as an implicit repair of the vulnerability.
- Independent review must also cover #1289 strict target syntax, #1422
  private-lab classification, and #177 actual request-bound consent.
- Hosted checks at exact immutable SHA, registered self-hosted VPS
  execution, independent security/privacy review and explicit human
  release are distinct gates. None is conferred by these tests.

## Current HEAD validation discipline

A passing general unittest suite with three intentional expected failures is
**not** a repaired parser. Inspect the exact branch commit's CI jobs; hosted
GitHub Actions jobs are distinct from a job actually executed on the registered
permanent VPS runner. Never reuse an earlier SHA's green jobs as proof after a
new test/documentation commit. The local negative cases are expected to remain
RED until the production source owner repairs the identity boundary.

## Distinguishing synthetic and real permits

The new `ActivationGate` expected-RED case instantiates a purely in-memory
fictional `Authorization` and asks the real production gate to deny an
unrelated bare IPv6 target. Current source instead produces a synthetic
`ExecutionPermit` bound to the truncated hextet. No adapter executes, no
customer has consented, no network traffic occurs, and the returned object is
not a real authorized grant. Both PLAN_ONLY and LAB_ONLY are checked as green
denial comparators; neither permits the same request. This is an explicit
acceptance requirement for the existing source owner, not a proposal to
activate targets.

## Privacy/scope fixture improvement

All executable test inputs now use **RFC 3849 documentation-only IPv6
addresses** (`2001:db8:1::1111`, `2001:db8:2::2222`,
`2001:db8:3::3333`) rather than routable public-server addresses. The
separate synthetic DNS label `2001` collides with the current parser's
first-hextet truncation without involving a real endpoint. For explicit
/128 controls, `allow_private_lab=False` guarantees documentation address
classification cannot hide the explicit scope decision. DNS and socket
operations remain blocked by the actual test guard.

## W3: independently enumerated identity-collision matrix

A fifth installed-source expected-RED test evaluates **all 256** distinct
canonical RFC 3849 test addresses `2001:db8:<0000..00ff>::1` with a
fictional `explicit_hosts={"2001"}` and synthetic in-memory Authorization.
It **materializes all 256 decisions before asserting**, rather than stopping
on the first counterexample. Current main falsely maps all 256 to a
host-allowlist admission; the assertion message includes the exact count.
The independent witness requires that count in the expected RED traceback,
rejecting masked TypeError or early failures. The seventh ordinary comparator
re-evaluates all 256 corresponding bracketed forms and proves **256 denials**
against the unrelated DNS label, with exact preserved IPv6 identity.
Neither path uses sockets, DNS, real assets, imports any live worker or
issues an active permit. This matrix is still a source-owner acceptance
contract, **not** an implemented production fix or authorization grant.

## W4: permit token-creation boundary, not merely a scope verdict

The sixth real current-main expected-RED case drives **128 distinct RFC3849
IPv6 targets** through the installed `ActivationGate.issue()` in synthetic
AUTHORIZED mode. A narrowly patched `lightup.activation.token_urlsafe`
returns only the fixed literal `FAKE-NON-LIVE-TOKEN`, recording every attempt.
It proves **128 token-generation attempts for 128 wrong-host identities**,
instead of only demonstrating a `ScopeDecision` mismatch. No real secret,
customer authorization, persistent grant, network request or adapter exists.

The eighth independent green control supplies a missing, expired and
future-dated fictional Authorization to the same bad lexical host under
AUTHORIZED mode. All are denied **before** `token_urlsafe` may be invoked.
That proves ordinary temporal gates still reject those three conditions,
while establishing that they do not rescue a valid-looking, wrong-identity
synthetic request.

Both are pure in-memory acceptance only. The real source owner must deny
wrong-host admission before any permit/token generation; the isolated tests
do not repair runtime source or authorize any real execution.

## W5: end-to-end positive scope remains exact, never broadens

An additional independent normal-green test constructs **64 separately
configured canonical bracketed IPv6 /128 targets** in RFC3849 documentation
space. Using a fixed fake token response, each in-memory AUTHORIZED
`ActivationGate.issue()` permit **must preserve the full exact IPv6
identity**, capability, mode and explicitly fake token. It then
tries **64 unrelated /128 IPv6 addresses** with the same fictional claim,
which must all be denied by the *actual* gate.

This is important after the production owner fixes bare IPv6 parsing:
the repair must not break the existing safe bracketed IPv6 route,
and it must not turn a single /128 grant into a whole IPv6 prefix,
generic host or sibling-network grant. All 128 interactions are
pure in-memory, with DNS/socket tripwires; no network target,
durable grant or adapter has been contacted.

## W6: spelling-independent source identity and non-authority

The next **1,024 distinct bare IPv6 string spellings** cross 256
independent RFC3849 documentation IPv6 identities with four ordinary
lexical spellings: compact lowercase, compact uppercase, fully expanded
lowercase and fully expanded uppercase. Every form is explicitly
evaluated against the same unrelated synthetic DNS host allowlist
`{"2001"}`. The seventh installed-source expected-RED aggregates all
1,024 wrong-host matches rather than terminating at the first.
The existing RED-integrity witness now rejects masking or accidentally
green outcomes for this new case.

A tenth normal comparator probes the same **1,024 bracketed forms**:
all must remain out of scope for the unrelated DNS hostname, and the
normalized identity must parse as the *same exact IPv6 address*
regardless of cosmetic case/compression. These 2,048 decisions prevent
a repair that merely handles one textual form yet continues to grant a
different identity for uppercase or expanded input. Inputs stay
documentation-only; no network, real authorization, adapter, permit
issuance or deployment.

## W7: exact asset-binding compatibility with source-owner #100

The active source-owner #100 adds `Authorization.assets` and compares
`allows_asset(normalized_host)`. Read-only inspection of that PR's
**actual changed `scope.py`, `models.py` and `activation.py`**
confirms that the broken lexical `normalize_host` function is not yet
repaired, so comparing the *already truncated* `2001` to an otherwise
matching fictional asset `("2001",)` still does not establish rights
to `2001:db8:1::1111`. I sent the exact ordering and acceptance
requirements directly to source-owner PR #100 without modifying it.

Two further expected-RED methods now work in **both** the original
main model (which lacks `assets`) and the source-owner model (which
provides `assets`). They instantiate a fictional asset `"2001"`
only when the actual Authorization dataclass has that exact field,
then exercise **the installed real ScopePolicy and ActivationGate**:
neither may grant the mismatched IPv6 literal, regardless of a claimed
permission. The shared fixture helper also binds the exact IPv6 asset
in ordinary safe bracketed /128 positive controls, so future
source-owner tests will still prove good decisions instead of being
masked by an empty-assets default. Missing/expired/future authorizations
retain valid hypothetical asset scopes, testing real temporal rejection.

The primary hosted job for current main is not proof that #100's
proposed code itself has run these tests: they are **portable future
source-owner acceptance**, not CI evidence of the unmerged owner branch.
No source-owner file or worker branch was changed.
