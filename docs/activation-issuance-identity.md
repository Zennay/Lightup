# Activation issuance identity boundary (#1517) — DRAFT/HOLD

This is a **production-source bug fix**, not a new grant system or a release approval. The future-adapter `ActivationGate.issue()` used to run `ScopePolicy.decide(target)` and then independently re-read `target.authorization`. The public `Target` / `Authorization` dataclasses are frozen only by normal attribute assignment; an in-process callback can still swap fields with low-level mutation. That allowed the scope decision and the permit provenance to refer to different target or authorization inputs.

## Implemented behavior

- Capture the **exact canonical** `Target.value`, `Authorization.owner`, `reference` and optional timezone-aware built-in `datetime` bounds before calling the scope policy. Do not execute client-provided subclasses or equality methods.
- Make the actual scope decision against this detached snapshot rather than a mutable caller-owned object.
- In AUTHORIZED mode, require a nonempty owner and reference, and verify the **captured** authorization window at the recorded UTC permit issue instant. Missing, malformed or changed provenance fails closed.
- Before issuing the permit, re-read the original caller fields independently and compare against the snapshot. If the policy mutated even the detached snapshot, fail closed as well. Do not return a permit when the decision and recorded provenance disagree.
- Keep PLAN_ONLY denial and LAB_ONLY private/loopback restrictions intact. No new tools, target access, network calls, grants, callbacks, scanner, handlers, workflow changes or implicit authority.

## Important limits

This check reduces **in-process decision-to-issuance identity drift**, including the #1517 change-after-decide example. It does not establish that a real request was approved, that authorization is durable, that any revocation remains valid at execution time, or that concurrent mutation cannot occur after the final comparison. Permits are not cryptographic signatures and do not allow future tools to skip **fresh** tenant, asset, capability, risk, consent and revocation checks at the actual execution boundary. The separate #177/#673/#829 source-owner work remains required.

Project posture remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. Integration, merge, real deployment and any active operation require independent source-owner/security/privacy review, authenticated distinct client and operator consent, revocation at use, all original exact-head mandatory hosted and named-permanent VPS CI and explicit human GO. No QA/regression tests have been authored or run in this change (17 October 2026 execution instruction); syntax/build inspection only.

## Policy and capability identity guard (follow-up)

The same source issue also leaves `ActivationPolicy` externally mutable despite its frozen dataclass, so the gate now snapshots its exact mode and activation reference and rejects policy changes before returning a permit. An untrusted capability argument must be a nonempty, bounded, control-free builtin string before a permit can be produced. The returned permit always contains the policy mode from the checked snapshot, not a newly read mode. These are issuance-only constraints, not proof that any capability was approved by a human or a durable source grant.

## Grant object substitution fence

A freshly constructed `Authorization` instance with the same visible owner/reference/window is **not** the same object as the original caller authority. The gate now also pins both the original and independent scope-snapshot authorization **object references**. A substitution to a same-valued new instance on either side results in HOLD before permit issuance. This is local object-provenance consistency only, not durable grant-ID or issuer verification and not a proof against all concurrent swaps.

## Bound policies and returned decision integrity (#1476, #1482)

At gate construction the actual original scope/activation-policy object references and strictly canonical copies of their built-in values are retained. At issuance, switching either policy object (even for a same-valued alternative) or changing its canonical fields fails closed. Scope is decided from the copy, not from a potentially rebound field. Both original object references and their values are checked again before a permit is returned. A policy decision must also be an exact `ScopeDecision` containing an exact boolean, a real `ScopeReason` member, and a plain normalized host identical to the current detached target normalization; ambiguous or forged decisions cannot flow to a permit. This fixes the in-process policy rebinding and decision-envelope gaps, but cannot attest to long-term consent or source database approval.

## Gate construction and immutable normal reconfiguration

The gate now validates the *exact original* scope and activation-policy types and value snapshots before invoking any caller-provided validation method; only the canonical copied ActivationPolicy receives validation. After successful constructor completion, the gate is sealed with fixed slots and refuses ordinary attribute assignments, including attempts to replace scope/activation policy handles or its stored snapshot fields. The prior independent issuance-time policy/reference and value checks remain mandatory as defense in depth. Ordinary Python immutability is not a sandbox against hostile in-process `object.__setattr__` or native mutation; the real authorization and revocation check must still occur at the future actual action boundary.

## Installed capability admission (#1511)

LAB_ONLY and AUTHORIZED issuance no longer accept arbitrary caller-provided capability names. Every ID must be an exact built-in lower-case, hyphen-separated ASCII slug no longer than 128 characters, and must match an exact installed ID from the existing read-only capability inventory. Unknown, Unicode-confusable, polymorphic, unbounded or missing IDs fail before a scope decision. This inventory existence check does **not** check that a specific real customer approved a capability, does not imply that a PLANNING capability may be dispatched, and does not override existing registry state, explicit client/operator authorization or future execution-time gates. The historical `web-baseline` private lab example remains an installed ID; no active capability has been enabled by this change.

## Explicit lab session provenance (#1487)

Every LAB_ONLY gate now needs its own caller-supplied, canonical, exact built-in string activation reference. The old implicit generic `LAB` default is removed; empty, whitespace, polymorphic, unbounded and control-character-laden references cannot create a lab permit. This makes provenance reviewable but does not attest to an authenticated lab session or grant authority. PLAN_ONLY remains denied, public targets remain excluded from LAB_ONLY, and authentic consent/revocation/registered CI gates remain separate. Existing expected-RED owner contracts must be deliberately reconciled with the source repair; no test markers are skipped or rewritten here.
