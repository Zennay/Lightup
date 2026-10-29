# LightUp default web security integrated candidate

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. NOT A RELEASE.**

## Concrete integrated source
This *single source branch* combines the **exact original** cookie envelope guard from [#1169](https://github.com/Zennay/Lightup/pull/1169) with the normal Gunicorn production factory wiring from [#1612](https://github.com/Zennay/Lightup/pull/1612), and the complete authored production `LightUpWebApp` source from [#1609](https://github.com/Zennay/Lightup/pull/1609).

Operator/client flow through the normal configured Gunicorn factory:
1. Original configured strict TLS origin and loopback peer security is constructed; pre-auth cookie envelope wrapper rejects ambiguous, malformed and duplicate session credentials with generic 400 and fixed headers before session or body access. Original `DomainStore.session_context` remains the only session authority.
2. Handler errors from `KeyError`/`ValueError` no longer reflect raw exception messages/client-supplied IDs in authenticated 400 bodies; standard Response security headers remain.
3. A signed-in operator may GET/view client portal read-only, never see the client submission form and cannot POST client assessment requests using a synthetic client admin context. A real same-client user retains the original form/handler flow and CSRF/session requirements. Original independent domain trust fix #1570 still needs source-owner composition.

## Source and ancestry
- Immutable base commit: `b426b29eeb73444c0eba027ae95cf7bd97a6afcc` from existing independent #1612 production-cookiefactory branch (which itself retains original #1169 ancestry).
- App source is copied from latest original authored #1609 source; no edits to its original branch or to other owners' `domain.py`, security settings, CI/workflows/tests, reverse proxy, scanner, lab/target/execution/grants or activation code.
- This integration is not intended to jump ahead of independent #1169/#1612/#1609 original owner approvals. It is a **single integrated review candidate** and intentionally stays draft/HOLD; do not use GitHub mergeability as authority.

## Explicit remaining blockers
Browser cookie compatibility and real installed Nginx/Gunicorn wire-header normalization review; independent web/domain/auth/security/privacy owners' source acceptance; original exact-head hosted and permanently registered named VPS CI; real separate authenticated client/operator consent and at-action revocation; HUMAN GO. No testsuites/QA authored, extended or manually run; no real customer data, target network call, grants, scan, release, deployment or operator authorization claim.

## Fourth source capability — safe real tenant finding CSV export
The combined candidate now also includes the *unmodified* original Unicode/full-batch validator source `src/lightup/finding_export_unicode_integrity.py` from [#1195](https://github.com/Zennay/Lightup/pull/1195) exact SHA `8ef5534d8520df30f6ae50a1114912ceb3a9eba8`, together with the previously-authored [#1611](https://github.com/Zennay/Lightup/pull/1611) tenant-service integration source.

The ordinary tenant-selected `render_client_findings_csv` now requires complete source-field/batch/Unicode/formula-prefix admission before any CSV output. Client/engagement lineage is resolved through the original read-only `DomainStore` paths *before* serialization. An invalid late record prevents partial output. The original low-level `render_findings_csv` remains callable for separate internal consumers; those direct callers do not gain automatic protection. The existing web error confidentiality source means client-visible domain validation exceptions no longer expose their raw values.

Existing source-owner acceptance on historical #1195/#1183 remains intact and unmodified. Old negative control suites on this ancestry intentionally presume the unguarded tenant producer; the original suite now reports errors after genuine source hardening. Original QA/source owners must deliberately reconcile those controls as part of integration; **never skip CI or remove witnesses**, and no QA/tests authored/changed/manually run in this iteration.
