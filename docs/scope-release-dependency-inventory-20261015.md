# LightUp — offline scope release dependency inventory (2026-10-15)

**Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

This is an **uninstalled, non-authorizing** local review aid, not an authorization or deployment workflow. The source owners of [live grants/revocation #107](https://github.com/Zennay/Lightup/pull/107), [risk-5 step-up #1172](https://github.com/Zennay/Lightup/pull/1172), [pre-handler evidence #1454](https://github.com/Zennay/Lightup/issues/1454), [legacy window #301](https://github.com/Zennay/Lightup/issues/301) and [permanent runner #1144](https://github.com/Zennay/Lightup/issues/1144) remain independent. Only three new owned files are added; none of those owners' files or source/runtime/runner/workflow settings are modified.

## Usage

The tool receives only *fictional* status declarations, never customer identities, tokens, targets, consent records or grants. Input shape is a strict JSON object with exactly 'schema' (integer 1) and 'checks' (one entry per gate). Each status is exactly 'MISSING', 'BLOCKED', or 'SELF_REPORTED'. No status is equivalent to verified permission.

Example via standard input:

    {"schema":1,"checks":{"client_consent":"MISSING","asset_and_capability_scope":"MISSING","live_grant_and_revocation":"BLOCKED","operator_step_up":"BLOCKED","durable_prehandler_evidence":"BLOCKED","installed_ingress_and_egress":"MISSING","permanent_vps_ci":"BLOCKED","independent_security_privacy_review":"MISSING","explicit_human_release":"MISSING"}}

    python scripts/scope_release_dependency_inventory_20261015.py < fictional.json

Every execution returns **exit code 2** and 'status=HOLD'. All six flags remain literal false: scan_allowed, grant_allowed, dispatch_allowed, merge_allowed, deploy_allowed, release_allowed. The result lists gate identifiers in stable order, never input details. Even nine SELF_REPORTED statuses produce HOLD; an empty needs_attention list is not a release signal.

A strict 8192-byte predecode input ceiling, UTF-8 decoding, duplicate-key refusal, exact schema and status type checks, and constant nonfinite refusal prevent ambiguous synthetic checklist intake. Malformed/over-budget input yields a generic, privacy-preserving HOLD.

## Mandatory independent evidence

| Gate ID | Missing trusted evidence required before release |
| --- | --- |
| client_consent | Genuine recorded client purpose-specific approval |
| asset_and_capability_scope | Trusted asset, capability, risk identity |
| live_grant_and_revocation | Current durable same-tenant grant and at-use revocation |
| operator_step_up | Separate current operator authorization for elevated action |
| durable_prehandler_evidence | Durable attempt/provenance before handler side effects |
| installed_ingress_and_egress | Installed Nginx/Gunicorn identity plus lab egress fence |
| permanent_vps_ci | Original exact-SHA jobs on permanently registered VPS |
| independent_security_privacy_review | Independent security and privacy sign-offs |
| explicit_human_release | Explicit named human GO after all independent proofs |

## Tests and limits

Run:

    python -m unittest discover -s tests -p 'test_scope_release_dependency_inventory_20261015.py' -v

Twelve local test groups exercise invalid, oversized, polymorphic, duplicate and nonfinite JSON, stable ordering, all nine gates, real subprocesses and no secret reflection. Synthetic green is not integrated production proof. This helper cannot attest GitHub, Notion, runner registration, consent, source-repair or installed ingress; self-reported claims remain unverified. In particular #301's expired test fixture and missing permanent runner proof may independently keep the repository's full release gate red.

**Do not merge, deploy, grant real authority or scan targets based on this packet.** Owner fixes, exact-head hosted plus permanently registered VPS evidence, privacy/security review and human approval stay outside this work.
