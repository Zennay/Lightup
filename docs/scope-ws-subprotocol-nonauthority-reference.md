# Scope authorization: WebSocket subprotocol is non-authoritative

**Status:** offline reference / HOLD. No production gate, network calls, upgrade handshake, grant issuance or target activity.

The client-controlled `Sec-WebSocket-Protocol` handshake header selects an application wire protocol; it is never an issuer signature, operator approval, capability lease, risk authorization, tenant identity, asset identity, grant revision, or revocation state. Header casing and arbitrary token contents must not change grant decisions. Even strings such as `approved`, `admin`, or `scope:all` confer no authority.

The standalone `tests/test_scope_ws_subprotocol_nonauthority_reference.py` uses an intentionally small frozen grant model and a mock call counter. It covers unapproved/revoked grants, identity/capability/revision mismatches, malformed persisted grant field types, exact grant class identity (including subclass rejection), stale revision replay, immutable presentation input, benign valid-grant controls, and no handler calls on denial. Thirteen offline unittest methods total. A dedicated fixture-integrity regression asserts that newline, NUL, zero-width, line-separator and surrogate test values are actual single Unicode codepoints with expected categories, preventing false confidence from accidental double-escaped string literals. The new identity hardening rejects leading/trailing whitespace, Unicode control/format/surrogate/line-separator characters in matching stored and request identities, and string subclasses; benign Unicode exact matches remain valid while composed/decomposed variants remain distinct. This is an offline reference contract, not production enforcement.

Production acceptance belongs to the WebSocket gateway / trusted scope executor source owners: use live authenticated authorization from server-side storage, enforce revocation and exact capability/asset/tenant binding immediately before side effects, reject invalid scope with zero handler/evidence side effects, and run exact-head hosted plus permanent VPS CI and review. This reference deliberately does **not** assert those production guarantees.

No overlapping production paths have been modified. No target I/O, scanning, deployment, or merge permitted by this artifact.

## CI regression and exact fixture repair (2026-10-09)

Hosted preflight `37914098987` failed (Python 3.11 and 3.14 `Compile and unit suite`, 20 assertions) because literal double-backslash fixture strings did not represent Unicode control characters. The self-checking fixture test exposed this failure; importantly, the preceding green-looking deny assertions were not trustworthy. Commit `4a08402fe529c52b18cd7bee7158048f397ef980` replaces double escapes with Python single escape sequences; GitHub source re-fetch confirms single-escape spelling. Exact-head hosted preflight `37914223989` and permanent VPS `37914223974` must pass before marking fixed. The reference does not establish production enforcement.

## Missing grant and presentation shape rejection

Three additional in-memory unittest methods cover absent/dict-like grants, malformed **requested** revision types, and header objects of arbitrary shape. The reference intentionally does not parse headers, because handshake negotiation metadata must never repair missing authorization evidence. **16 test methods** now exist in this standalone test file. This is not production enforcement; the real dispatcher and websocket gateway require source-owner verification and exact-head CI.

## Denied-dispatch matrix and positive control

Two additional standalone tests exercise eight denied grant/request combinations and assert zero mock handler calls, plus one fully matching approved control that reaches the mock handler once. Total: 18 offline unittest methods. These assertions prove only this in-memory reference, not the real production ToolExecutor, its I/O order, or durable revocation.

## Complete ASCII control and explicit authority-token deny matrix

Two more offline tests cover all 33 ASCII C0/DEL codepoints across the three grant identity roles when stored and requested values match (99 denial assertions), and ten authority-sounding WebSocket subprotocol values against explicitly unapproved consent. Total: 20 standalone unittest methods. Still reference-only, no production authorization evidence.

## Additional mutation and consent-denial mock checks

Two offline methods cover 15 cross-field identity mutations with zero fake handler calls and the three denied approval/revocation Boolean combinations. Total: 22 offline unittest methods. This does not prove real executor dispatch ordering, live revocation, or production WebSocket gate behavior.

## Revocation and malformed approval mock-denial expansion

Two additional offline methods verify that a header cannot undo revocation even when another identity role varies, and malformed approval types (null, integer, string and containers) produce zero fake handler calls. Total: **24 standalone unittest methods**. These do not establish real gateway or ToolExecutor authorization safety.

## Stored-grant authority cannot be overwritten by request fields

Two extra offline methods reject request-side self-approval against an unapproved stored grant and request-side `revoked=False` against a revoked stored grant. Both operate without handlers or targets. Total: **26 offline unittest methods**; still not a substitute for real trusted source-owned pre-I/O authorization.

## Control-codepoint mock-dispatch and malformed header container (2026-10-09)

Two additional offline methods assert 99 C0/DEL identity-role mutation denials lead to **zero fake dispatches** and verify revoked grants remain denied with arbitrary header-container shapes. Total 28 methods. This remains a self-contained reference, not real ToolExecutor enforcement.

## Sequential revocation and revision transitions

Two new offline tests demonstrate that a local reference grants one handler call before revocation but none after a stored revocation transition, and a new stored revision rejects the old request until a matching request exists. These are illustrative sequential checks, **not** evidence of concurrent or durable production revocation. Total: 30 unittest methods.

## Revoked replay and revision claim regression

Two new offline methods check twenty repeat requests after stored revocation result in zero mock calls, and a claimed future revision in WebSocket subprotocol never upgrades an older stored grant. 32 reference unittest methods total; this does not prove production durable revocation or live dispatcher safety.

## Replayed authority tokens and malformed stored revision

Two additional offline methods cover 35 attempts to replay seven authority-sounding subprotocol tokens against revoked consent with zero fake-handler calls, plus malformed stored revision values matched against a valid request. Total: **34 unittest methods**. No actual production executor calls or live revocation guarantees.

## Header casing and no header-access dependency

Two isolated offline methods ensure an unapproved stored grant is denied under four alternate `Sec-WebSocket-Protocol` header casings and absent grants are denied without reading a hostile header object. Total: **36 offline unittest methods**. The reference's explicit ignore-header design cannot substitute for gateway or ToolExecutor integration proof.

## Production integration acceptance handoff

Reference test count: **38**. The latest additions test a stored grant's independent authority even when caller request claims approval, and valid grants remain unaffected by unusual subprotocol presentation values.

**Source-owned integration gate (not implemented by this PR):**
1. Bind the server-side authenticated grant to tenant, asset, capability and revision; reject missing or malformed provenance before invoking any ToolExecutor, handler, DNS or socket operation.
2. Re-read revocation from a durable trusted source immediately before dispatch; never infer from a WebSocket subprotocol value.
3. In the real gateway and ToolExecutor integration tests, track handler and evidence writes for denied requests and require exactly zero; include a fully authorized positive control.
4. Execute Python 3.11/3.14 hosted preflight and permanent VPS suite on the **same reviewed implementation SHA**, then obtain source-owner review.
5. Preserve analysis-only posture until all gates pass. This PR does not activate assets or prove production safety.

## Compound header claims and request-state denial

Two offline methods assert denial remains monotone as caller-controlled WebSocket subprotocol claims accumulate, and valid stored consent cannot permit an invalid requested approval/revocation/revision state. Total: **40 unittest methods**. Only reference behavior, no production integration proof.

## Polymorphic equality spoofing

Two additional offline methods prove subclasses overriding equality cannot impersonate a trusted Grant or a request identity. The exact-type checks must precede any equality comparison. Total: **42 offline unittest methods**. No production implementation or actual handler integration is implied.

## Source-owner integration sign-off matrix (draft, lab only)

The **43rd offline method** instruments simulated handler, evidence-write and network-open boundaries: four denied grants create zero mocked effects, and the matching authorized grant produces one of each. This is **not production dispatch coverage**.

Before promoting a real gateway/ToolExecutor implementation, a source-owning worker must add separate real-code tests for these independent conditions:

| Boundary | Denied case | Required observable evidence |
| --- | --- | --- |
| Authenticated caller -> trusted grant lookup | no owner authorization / wrong tenant | no ToolExecutor, DNS, socket, or evidence write |
| Asset + capability binding | mismatched asset or elevated action | zero handler and network invocation |
| Grant revision and scope fingerprint | replay of superseded grant | zero dispatch and explicit denial reason |
| Durable revocation | revoke between admission and pre-I/O check | zero dispatch, including parallel workers |
| Positive authorized control | exact owner-approved lab asset and allowed operation | one deliberate sandbox handler call only |
| Header negotiation | spoofed `Sec-WebSocket-Protocol` privileges | zero elevation; no header-derived grant |
| Persistence + logging | denied operation | bounded denial audit only, no action evidence |

Collect proof on the **same exact implementation SHA**: Python 3.11 + 3.14 hosted runs, canonical permanent VPS run and owner review. Do not treat mock calls as actual I/O assertions, do not activate external targets and do not merge this reference branch without authorization.

## Revocation and Unicode normalization boundaries

Two added offline tests exercise denied mock executor effects after revocation even when requested state otherwise matches, and prohibit cross-normalization Unicode identity binding without explicit trusted canonicalization. A composed identity still provides the reference positive control. Total **45 unittest methods**. No claim of live dispatcher safety.

## Structural type rejection and negotiation-header access isolation

Two offline methods cover six malformed stored/request grant shapes (twelve deny assertions) and verify that deliberately hostile header mappings cannot be read as authorization inputs for rejected or accepted reference grants. Total **47 offline unittest methods**; no production ToolExecutor binding.

## Mutable negotiation-header invariance

Two extra offline methods verify denied trusted consent remains denied while the same caller-owned header mapping is repeatedly mutated, and valid matching consent remains allowed irrespective of five such changes. Total **49 offline unittest methods**. This is reference-only, not a claim that the real production gateway ignores headers.

## Explicit-denial dominance and reapproval revision fencing

Two offline tests check 12 pairings of denied approval/revocation states with authority-sounding WebSocket claims, and verify that reapproval on a newer revision cannot validate either a revoked earlier grant or a stale request. Total: **51 offline unittest methods**; real pre-I/O enforcement is not proven.

## Stale revision replays and strict revocation types

Two additional offline methods ensure three stale-revision replays produce zero mock execution effects and a new revision only allows an exactly matching request; malformed revocation fields are rejected without truthiness coercion. Total **53 reference unittest methods**. Real production pre-I/O safety remains outside this test model.

## Header-sourced identity and revoked matching revision

Two offline tests confirm caller-supplied WebSocket tokens cannot repair a wrong tenant binding, and that a matching revision does not overcome stored revocation or dispatch mock work. Total **55 unittest methods**. No production enforcement is claimed.

## Request approval replay and capability escalation

Two new offline tests reject ten attempts to replay an approved request against unapproved stored consent with zero mock handler calls, and reject any client-provided subprotocol capability claims that seek active-scan privileges beyond a read-only stored grant. Total **57 offline unittest methods**; production execution remains unverified.

## Repeatable denial and strict capability binding

Two additional offline methods assert identical denied grants remain denied after mutation of the same caller-owned header mapping, and active-scan claims cannot widen trusted read-only capability while the legitimate read-only positive control remains allowed. Total: **59 offline unittest methods**. This is no proof of a production pre-I/O gate.

## Evidence-based production handoff / release gate (2026-10-09)

These 59 methods exercise an isolated pure reference function. They **do not test** the actual WebSocket upgrade path, authenticated grant source, production ToolExecutor, persistent revocation store or outward effects. Method count must not be interpreted as production confidence.

Before promotion the owning implementation worker must attach evidence at one exact reviewed implementation commit:
1. Server-derived principal and trusted owner-approved grant, exact tenant/asset/capability binding; never source authorization from negotiation headers.
2. Durable revocation and revision re-check at the actual pre-I/O boundary, including a simulated concurrent withdrawal between admission and dispatch.
3. Instrument real handler entry, DNS/socket open, queued jobs and action evidence writes. Denied requests must cause **zero** of each (denial-only audit logs may still be permitted).
4. Include an explicitly approved owned lab positive control that performs only the permitted action.
5. Attach Python 3.11 and 3.14 hosted preflight **and permanent VPS** CI passing on this exact implementation commit. A previous-HEAD success or queued/cancelled VPS run is insufficient.
6. Source-owner review of any real-code modification and integration paths. This PR remains draft reference-only; do not take files from concurrent production workers.

**Release decision: HOLD.** Neither this document nor a passing mock test authorizes target I/O, merge or deployment.

## Offline multi-boundary side-effect instrumentation

The **60th reference unittest method** records simulated handler, socket, queue, and action-evidence side effects: revoked and unapproved stored grants result in zero of all four, while the authorized positive control reaches each exactly once. These are local counters only, **not a real ToolExecutor, network or storage integration test**.

## Distinguish denial audit from action evidence

The **61st offline unit test** captures an ordered synthetic gateway event trace. Revoked and unapproved requests may record a narrowly-scoped `denial_audit` marker while emitting **zero** `handler` and `action_evidence` events; a matching authorized request emits the two action events only. This is an offline mock, not a real gateway, logging subsystem or storage proof. Production source owners must verify actual persisted audit/evidence separation before promotion.

## CI evidence checklist (fill using real owner-owned integration runs)

Evidence is acceptable only when every check below references the **same source commit**. The standalone reference's passing results do not satisfy the integrated executor gate.

| Proof | Evidence to attach | Unacceptable substitute |
| --- | --- | --- |
| Trusted principal and grant | integration test path and log proving server-side grant lookup | copying `Sec-WebSocket-Protocol` or client fields |
| Revocation fence | durable storage epoch + pre-I/O test covering concurrent withdrawal | only checking revocation at admission |
| Denied real side effects | zero handler, DNS/socket, queue and action-evidence counts in real implementation logs | counts from the mock reference here |
| Authorized positive control | exact approved lab target and allowed action, confirmed by owner | a live unknown target |
| Hosted validation | Python 3.11 and 3.14 green workflows for reviewed commit | partial/in-progress or preceding head |
| Permanent VPS validation | green canonical VPS workflow for reviewed commit | queued, cancelled, retriggered but incomplete run |
| Code owner approval | approved production PR and conflict-free change ownership | draft or unrelated review |

Until the owner provides all seven evidence artifacts, keep this standalone PR as **DRAFT/HOLD** and avoid any production activation.

## Trusted reapproval transition and action trace

The 62nd and 63rd offline unittest methods check that reapproval requires both a changed trusted stored grant and an exactly matching fresh request revision, and that six arbitrary negotiation-header payloads against revoked consent never create mock handler, queue or action-evidence events. This validates the reference only, not a durable production revocation store.

## Revoked replay event trace

The **64th offline unittest method** simulates twelve repeated requests with revoked stored consent and asserts only denial-audit markers, never action markers. This models reference idempotence, not real persistence, revocation races or production execution.

## Stale revision denial audit separation

The 65th offline unittest method covers eight replayed outdated-revision requests; every synthetic trace entry must be a denial-audit event and none may be action evidence. This remains a mock decision contract, not production integration evidence.
