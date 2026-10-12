# Scope authorization #297 — atomic public policy shape review (2026-10-12)

**Release posture:** LightUp Incubate / M3-M7 PLAN/LAB only. **DRAFT / HOLD / NO MERGE / NO DEPLOY.** This isolated reference is not installed in the default `ScopePolicy.decide`, `ToolExecutor`, or ingress path; it cannot authorize a target or issue a digital grant.

## Reproduced defect and boundary

Issue [#297](https://github.com/Zennay/Lightup/issues/297) describes path-dependent validation: a malformed `explicit_networks` entry is only parsed for an IP-literal target, while a hostname in `explicit_hosts` can reach an allowed `EXPLICIT_HOST` decision without network-list validation. Real authorization requires a separate trustworthy grant and must be evaluated at dispatch. Current code has not been repaired by this change.

## Material implementation (strictly add-only, separate ownership)

- `src/lightup/scope_public_config_integrity_20261012.py`: opt-in **deny-only syntax/shape validation**; exact policy/boolean/container types, exact ASCII canonical hostname label syntax, canonical networks using `ip_network(strict=True)`, mandatory public authorization switch, and entire-set validation before any per-target branch. IP literals in the hostname set are refused (real `ScopePolicy` routes them down the *network* path), as are zone-scoped IPv6 network identities (`%eth0` etc.) and public-global `/0` wildcards. **Returns `None`, never a success/permit or grant.** It performs no DNS, socket or target I/O.
- `tests/test_scope_public_config_integrity_20261012.py`: synthetic offline suite with both positive and adversarial network/host inputs, poisoned second network entries, noncanonical aliases, type-confused subclasses, IPv6 interface-zone ambiguities, misplaced IPv4 literals, broad `/0` routes, precise `/32` and `/128` positive controls, purity and no-grant assertions. A separate `@expectedFailure` **RED** method documents the still-unfixed installed hostname branch. An XFAIL is not safe production acceptance.
- This document records handoff and rollout gates; no existing source-owner files changed.

Reproduce (offline, with source on PYTHONPATH):

```sh
PYTHONPATH=src python -m unittest -v tests.test_scope_public_config_integrity_20261012
```

## Boundaries and unresolved security work

1. This conservative reference demands canonical lowercase ASCII hostnames, normalized CIDRs, no IPv6 local zone IDs, no IP literals in the host collection and no Internet-wide `/0` wildcard routes. Compatibility, public network range budgets and any IDNA policy must be decided by scope-source owners before installing it; **do not** silently normalize inputs into wider authorizations.
2. In particular, shape validation is neither ownership consent nor per-asset authorization. Issuer, tenant, operator, grant ID, engagement, asset, capability, approved risk, validity window, live revocation, and pre-I/O race/lease revalidation remain independently required.
3. Legacy `Authorization` is still insufficient to prove trusted consent. Normal `ScopePolicy.decide` remains vulnerable to the #297 path gap until an owner-owned source repair is reviewed and integrated.
4. Independent review must reconcile public-host policy/URL/input guards and source owner PRs, then create **passing** real-producer tests against the installed integration point. Do not promote the RED characterization alone.
5. Approval requires exact-head hosted Python 3.11 and 3.14 unit + real-producer integration logs **and separately** an accepted registered permanent `[self-hosted, zcloud, vps]` LightUp CI run. Queued or cancelled CI is not a pass. Resolve current-main composition and obtain explicit human approval before any merge/deploy.

**Prohibited:** real clients, external targets, active scans, grants, assessments, remediation, retests, attack-path mutation, deployment or authorization widening. This is code + offline fixtures only.
