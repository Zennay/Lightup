# Scope #376 — fictional durable asset identity shape review (DRAFT/HOLD)

## Purpose and ownership
This isolated child work addresses [issue #376](https://github.com/Zennay/Lightup/issues/376) without editing the existing `DomainStore.record_authorization_grant`, `ScopeDefinition`, the domain owner #554, the public-scope owner #100, other worker branches, workflows, or runners. Branch created from current `main`; all three paths are new and dedicated to this review.

**INCUBATE M3/M7 · PLAN/LAB ONLY. No source integration, merge, deployment, customer grant, handler invocation, scanning, or release.**

## Exact delivered contract

- `src/lightup/scope_376_asset_identity_review.py`: optional, unwired pure review function `review_asset_identity_shape`. It accepts only an exact `ScopeDefinition` with an exact nonempty tuple of built-in canonical already-trimmed text allowlisted assets and an optional exact tuple of equally well-formed excluded assets. Each collection is bounded to 256 entries and each identity to 2,048 characters; control characters, subclasses, blank or untrimmed entries are rejected before any untrusted string overrides run.
- `REVIEW_ONLY` means only a conservative *shape* check succeeded. The frozen receipt is always false in boolean contexts, exposes six literal false authority markers, and never echoes targets, tenant IDs, consent references, raw input, or claims. `HOLD` is returned atomically for invalid shapes.
- `tests/test_scope_376_asset_identity_optin_20261016.py`: ordinary fixture-only checks, boundary limits, polymorphic string and scope rejection, mutation guards, no-I/O checks, a positive real SQLite legacy roundtrip, and three **deliberately OPEN original-source expected failures** against actual `DomainStore.record_authorization_grant`. A separate RED oracle requires all three source failures to remain real, not hidden successes or runtime exceptions.
- The reviewer does **not** establish DNS/IP identity, CIDR validity, Unicode equivalence, ownership, consent, client/engagement binding, revocation, allowed capabilities, expiry, temporal validity, exact self-hosted GitHub runner proof or human approval. It MUST NOT be used as a permit or wired to active execution.

## W2 receipt authenticity boundary
An additional hardening commit now refuses every status other than an **exact built-in** `HOLD` or `REVIEW_ONLY` when constructing an `AssetIdentityShapeReceipt`. Forged `APPROVED`/`PASS`/`RELEASED` strings, boolean statuses and `str` subclasses never become a receipt, and the new ordinary unit regression asserts no subclass comparison methods can be called. The serializer provides a **new ordinary dictionary**, which is a display artifact and can be modified by its recipient; neither it nor any client-submitted claim is an authenticated release decision. Six source-defined authority flags always serialize to literal false.

Do not reuse the older exact-SHA hosted results from W1 as proof of this W2 head. Verification must match the latest immutable commit.

## W3 — real disposable SQLite owner-adoption composition

The source owner now has **four new ordinary integrated test cases** in the *own* synthetic test file: the exact original `DomainStore.record_authorization_grant` method is locally wrapped for the duration of one test, and its `scope` argument is checked using the new optional reviewer **before** the same original insert call. Nine malformed allow/exclude scenarios then demonstrably leave the exact SQLite grant-row snapshot unchanged. A canonical fictional grant still round-trips through the genuine method with the temporary wrapper. The wrapper is restored by `unittest.mock.patch.object` in all cases; a final replay proves the **original unmodified source still persists** a whitespace exclusion, so these are compatibility/denial acceptance witnesses, **not** a source fix or actual operational grant.

The temporary wrapper preserves the original role check: no client role is promoted to operator. No public target, DNS, socket, scan, handler, external database, real customer data, real consent, tool call or grant authority is exercised. Tests intentionally create fictional records only in temporary local SQLite. They neither modify nor import the production owner PR branch; future source integration requires its owner's review, same-connection ordering and explicit release gates.

The **W3 immutable HEAD** and its newly triggered hosted/registered VPS jobs must be verified separately; W2's 11 ordinary green cases, three expected source-RED cases and unrelated #301 wallclock failure are earlier SHA evidence only.

## W4 — conservative hidden-whitespace rejection

The own optional pure shape checker now rejects **internal ASCII or Unicode whitespace** in allowlisted and excluded identities, including Unicode nonbreaking separators, tabs and line separators, rather than only trimming ends. These are **HOLD-only** syntactic counterexamples; no Unicode normalization, DNS resolution, alias comparison, registries or installed source owner paths were touched. Its existing canonical fictional ASCII host/IPv4 fixtures remain allowed for **REVIEW_ONLY** shape review, not execution permission. The own ordinary local unit controls and temporary same-call SQLite denial acceptance were extended to cover these internal-whitespace inputs. This is a deliberately conservative subset requiring owner review for non-ASCII legitimate names; issue #1437's Unicode alias metadata owner remains separate and untouched.

**W4 exact HEAD needs fresh test evidence**, not older W3/W2 logs. The unrelated #301 date-expired base test and permanently queued #1144 runner remain separate dependencies.

## W5 — exact duplicate/collision HOLD with no alias authority

After all items are proven **exact built-in strings** and bounded, the unwired review now rejects **exact duplicate** allowed or excluded assets and exact overlap of an allowlisted and excluded asset, instead of silently guessing the intended priority. This is a conservative intake HOLD requiring the source owner's independent policy review: exclusions overlapping allowed assets may have legitimate narrowing semantics, so these results MUST NOT be promoted to automatic production denial or considered authoritative without an explicit design decision. It makes **no** casefold, IDNA, Unicode normalization, DNS, or alias-equivalence claims; a case variant can remain **REVIEW_ONLY shape-only** while both authority and alias policy stay unverified.

Two new ordinary test methods cover duplicate/collision false receipts and explicit case-sensitive-only semantics. The previous 256-item inclusive positive boundary fixture now uses **256 distinct** fictional identities, and the exact temporary original-SQLite pre-insert preview also tests three extra collision inputs without writing a row. All existing source-owner gates remain unchanged and not installed.

**W5 needs new exact-HEAD hosted Python 3.11/3.14 evidence**; previous W4 logs cannot establish this implementation's test result.

## W6 — exact dataclass instance-field integrity

An additional non-authorizing safety gap was identified in the standalone opt-in reviewer itself. `ScopeDefinition` is a frozen dataclass but an in-process caller can use `object.__delattr__` or directly mutate `__dict__`. Reading `scope.excluded_assets` after deletion could silently fall back to the class default empty tuple, **losing an intended exclusion in the shape preview**; a completely uninitialized exact instance could raise `AttributeError` instead of generic HOLD. Neither is a verified production privilege escalation, but both are inappropriate review semantics.

The own pure helper now checks the exact native `dict` instance-field envelope of **exactly** four built-in string keys (`assets`, `excluded_assets`, `allowed_capabilities`, `max_risk`) *before* reading the values. It bounds count first and verifies key types before key-set equality, so malicious key subclasses cannot run their own comparison/hash methods during review. Missing, extra, uninitialized or nontext-keyed instances return `HOLD` with six false authority markers. This is conservative: if the original domain dataclass intentionally adds a field in future, the reviewer will HOLD pending owner review rather than assume compatibility.

Two ordinary regression test methods cover all four deleted fields, an uninitialized exact instance, an extra attribute and a poisoned non-string dictionary key. The real disposable SQLite test-only owner-adoption wrapper now includes a scope with a deleted exclusion and proves **no INSERT** occurs when the preview is required; on its own, the unchanged original production source is still not repaired. This reviewer must never grant rights or touch client data.

**W6 HEAD requires fresh evidence** from original hosted Python 3.11 and 3.14 logs, true producer integration and registered VPS runner; older W5 proof does not apply.

## W7 — reflective receipt tampering, scope snapshots and expanded true SQLite source REDs

Further **three distinct safety improvements** on this OWN draft lane:

1. Python `frozen=True, slots=True` is not a cryptographic security boundary. A caller can use `object.__setattr__(receipt, "decision", "APPROVED")`, delete the decision field or insert an untrusted `str` subclass. In W6, the serializer would echo forged status / raise for missing status. The receipt's `as_public_dict` now clamps every malformed, missing or non-exact `HOLD`/`REVIEW_ONLY` decision to **literal `HOLD`**; its six immutable false authority flags and false boolean still hold. A malicious `str` subclass's overloaded comparison is not invoked. The public `receipt.decision` property itself remains mutable through low-level reflection and **must never be treated as authentic or privileged**.
2. After checking a built-in four-entry `ScopeDefinition.__dict__`, the reviewer takes a bounded native `dict.copy` **snapshot** and validates both key envelope and actual allowed/excluded values from that same snapshot. This avoids using previously validated dictionary keys to read values from a different instance dictionary revision. It is still only a pure in-process shape-check, not a concurrency-safe, signed, persisted, consent-bearing or atomic authority decision.
3. Three new ordinary own methods cover reflection-mutated receipt serialization, deleted/excluded scope dictionary edits, and **512 deterministic malformed identifiers** in both allow and exclude (1,024 synthetic negative observations with no network I/O). Two new genuine **original-source** expected-failure acceptance cases now demonstrate that `DomainStore.record_authorization_grant` currently persists **a numeric allowlisted asset** and **a NUL-containing allowlisted asset**, in addition to the three earlier originals. The strict RED oracle requires **all five source defects** to remain visible; none are silently counted as a fix. The sample is purely fictional, under temporary local SQLite. Fixtures use actual Python unicode/tab/NUL escapes rather than literal slash-u/escape characters.

This addition is **not** the production source fix, an integrated guard, an issuer, evidence of consent or a permission for any target/scan. Original source owners #554 and #100 and other PR owners retain their files. Exact latest W7 SHA tests must be inspected afresh; W6 hosted green own tests and unresolved unrelated #301 full-suite failure are historical evidence, not W7 verification.

## W8 — strict no-DB-call denial seam and independent owner gate

Two more **ordinary original-method-seam integration tests** strengthen the safety contract without changing any production file:

- For fictional malformed numeric, NUL-containing, hidden Unicode whitespace and duplicate exclusions, the temporary test-only owner-candidate `record_authorization_grant` wrapper is run with BOTH the original persistence function and underlying `DomainStore._connect/get_engagement` replaced by strict canaries that would fail instantly if called. Rejection happens **before any original call, SQLite opening or engagement read**, and its generic ValueError never echoes a sensitive marker.
- A canonical fictional shape review is not itself an authorization. A separate owner-gate canary remains mandatory and raises `PermissionError` if no separate consent, tenancy or source checks admit the grant. The test proves the preview does **not** short-circuit this gate or insert a row into disposable SQLite. A positive REVIEW_ONLY decision is not a permit.

All tests remain synthetic with temporary local SQLite, no customer permission or tool execution. Nothing installs the temporary wrapper. These are acceptance/handoff constraints for the actual source owner, not evidence that production currently denies those malformed records. **Recheck the exact W8 immutable SHA hosted logs**, and retain DRAFT/HOLD under #1144 VPS queue and #301 base-test dependency.

## Owner decision needed
The existing domain/grant source owner should decide whether this narrow text-shape preflight, or an equivalent source-side guard, belongs directly before any persisted grant row. The reviewer ceilings are **illustrative** and may reject legitimate large scopes; do not treat them as approved product policy. If integrated, the original source must enforce the same reject-before-write semantics and preserve valid grant roundtrips. Convert the three original-source expectedFailure methods to ordinary PASS only after the actual production source is fixed and revalidated. Do not claim the opt-in helper fixes persistent authorization.

## Verification and gating
- Validate exact immutable HEAD with original GitHub-hosted Python 3.11 / 3.14 jobs and real producer integrations; inspect **exact-head** job logs. A queued or absent VPS job is not evidence of a successful registered permanent VPS test.
- Independently verify production composition, security/privacy, real customer and operator consent, current durable revocation, runner registration/labels, and explicit human GO before any release.
- Existing release/runner issue: [#1144](https://github.com/Zennay/Lightup/issues/1144). Existing original durable-resolver issue: [#639](https://github.com/Zennay/Lightup/issues/639). This branch does not change either owner's code.

**Status remains DRAFT/HOLD regardless of isolated successful tests.**
