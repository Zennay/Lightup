# LightUp scope-authorization #1489 — IPv6 interface-zone identity HOLD

Phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No merge, production release, deployment, grants or real targets.

## Installed-source defect (unchanged main)
ScopePolicy.normalize_host retains IPv6 bracketed zone suffix; Python ipaddress accepts scoped literals, and private/link-local/loopback classification can admit them as lab targets.

Reproducible *in-memory only* fictional Target strings:
- http://[fe80::1%25eth0]/ => current PRIVATE_LAB witness, expected DENY.
- [fe80::1%eth0] => current PRIVATE_LAB witness, expected DENY.
- [fd00::1%eth0] => current PRIVATE_LAB witness, expected DENY.
- [::1%lo0] => current LOOPBACK witness, expected DENY.

Zone labels are supplied by the caller and can change routing identity. They do not prove tenant, client or operator consent. No interface or target was contacted.

## Isolated deliverables
- tests/test_scope_ipv6_zone_1489_20261016.py invokes the installed ScopePolicy: four deliberately OPEN expectedFailure contracts, current-source witnesses, positive unscoped controls, and offline negative/replay/no-I/O tests.
- src/lightup/ipv6_zone_review_1489.py is a standalone strict canonical IPv6 shape diagnostic. Scoped IPv6 => HOLD, canonical unscoped IPv6 => REVIEW_ONLY. Both statuses guarantee literal false execution/permit/dispatch/release flags. It never echoes any input identity.

**The helper is NOT installed in ScopePolicy or ActivationGate. No production-source owner or other workers' files have been modified. REVIEW_ONLY does not grant authorization.**

Isolated command: PYTHONPATH=src python -m unittest -v tests.test_scope_ipv6_zone_1489_20261016

Inspect original Python 3.11 and 3.14 hosted job logs for four expectedFailures and zero ordinary failures in owned tests. Untouched main has a separate expired #301 date-fixture issue, so full preflight may be red for unrelated reasons. A hosted green test never substitutes for permanent registered VPS proof at exact HEAD.

## Required owner follow-up
1. Original src/lightup/scope.py owner (#100 and #1289 parser issue) reviews a fail-closed IPv6 zone rule before private/loopback classification; DO NOT strip zone syntax into unscoped auto-authorized IPv6.
2. Preserve behavior for canonical unscoped lab/loopback IPv6 until independently reviewed.
3. After genuine source repair, convert four expectedFailure REDs into ordinary passing source tests. Require complete preflight and integration matrix, independently registered self-hosted,zcloud,vps runner hostname vps-bb300bba, security/privacy, authenticated consent/revocation and human GO before release.

Issue: https://github.com/Zennay/Lightup/issues/1489
Separate unscoped special-use IP issue: https://github.com/Zennay/Lightup/issues/1422
Original parser issue: https://github.com/Zennay/Lightup/issues/1289