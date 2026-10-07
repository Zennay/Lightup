# Offline authorization denial review matrix

The machine-readable fixture at `docs/fixtures/scope-authorization-offline-review-v1.json` is a **review aid**, not an authorization grant, execution policy or source of truth. Its asset names use reserved `.example.invalid` identities only; local `.local` names and actual routable identities are forbidden. These names must never be resolved or contacted.

## Intended proof boundary

`tests/test_scope_authorization_offline_review_fixture.py` verifies that the fixture remains structurally stable and cannot silently acquire `network_access`, `active_execution`, or `external_targets` defaults. It also verifies the required negative scenarios remain marked `DENY`.

**It does not verify that production authorization enforcement actually returns those decisions.** Source-owning PRs #100 and #107 must establish runtime enforcement with independent tests, including canonical grant/provenance, asset exclusions, time windows, revocation, tenant isolation, operator approval, and prevention of post-issuance privilege widening.

## Review protocol

1. Keep the fixture and tests offline; never resolve fixture asset names. Preserve the exclusive `.example.invalid` naming rule.
2. For each negative row, link a specific runtime test with a fail-closed assertion before treating it as implemented.
3. Confirm analysis-only mode cannot acquire target/network access.
4. Do not change a row from `DENY` to an execution-allowing value merely to make a suite green.
5. Use the permanent self-hosted LightUp runner for exact-head CI. Do not merge this draft PR on fixture-only results alone.

## Local fixture-only check

`python -m unittest discover -s tests -p 'test_scope_authorization_offline_review_fixture.py' -v`

No production modules, active targets, network operations, workflow configuration or worker ownership are changed by this addition.
