# ScopeDefinition direct integrity pack

Issue: #776

Pinned parent: #554 exact head `4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

This branch composes three independent acceptance families without changing production source:

- #648 — mutable caller-owned collection snapshot/isolation;
- #773 — exact direct `ScopeDefinition.max_risk` runtime identity;
- #775 — exact built-in tuple containers and exact built-in string entries.

## Intended proof partition

Canonical controls remain green.

Expected-RED coverage is isolated to producer-impossible or non-canonical direct scope state until the active source owner absorbs equivalent constructor/policy guards:

- mutable list aliasing across assets/exclusions/capabilities (#648);
- raw integer, boolean and foreign-enum risk values (#773);
- tuple-subclass iterator/membership spoofing and polymorphic string entries (#775).

## Ownership

This is a composition/proof head only. It does not modify `src/lightup/**` and does not own the future repair.

Separate ownership remains with issuance validation (#376/#650/#646/#121), persisted execution revalidation (#639/#554), request-side runtime identity (#575/#576), outer direct scope identity (#740), and legacy Authorization scope contracts.

## Safety

Pure in-memory/temporary-state authorization narrowing acceptance. No target interaction, DNS/network I/O, scanning, handler execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
