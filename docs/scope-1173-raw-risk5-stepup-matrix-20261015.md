# Scope #1173 — independent risk-5 raw-executor step-up matrix (15 Oct 2026)

## Project state and safe boundary

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This branch starts from current `main` and changes **only two new, isolated acceptance artifacts**; it does not edit the source-owner `src/lightup/ai/orchestration.py`, `src/lightup/execution_policy.py`, #1172, #107, workflow/runner configuration, or other workers' files. It is **not a security fix**, customer grant, or permission to deploy or scan.

This supplements [open #1173](https://github.com/Zennay/Lightup/issues/1173), which already documents the opt-in [source-owning producer #1172](https://github.com/Zennay/Lightup/pull/1172). Do not silently merge, rebase atop, or edit that owner branch. Production integration remains with the relevant owners.

## What this code actually checks

`tests/test_scope_1173_raw_risk5_stepup_matrix_20261015.py` exercises real installed `ToolExecutor`, `ExecutionPolicy`, `RunContext.for_lab`, `ToolRegistry`, and a disposable SQLite `StateStore`. A single inert local handler returns fixed synthetic bytes. A socket tripwire rejects any network creation; the lower-risk positive-control handler is an inert stub with fixed synthetic evidence, not a live adapter. No customer, target, credential, scan, live adapter, real approval, or exploit exists.

Nine **intentional installed-source expected-RED** acceptance tests require:
1. Risk-5 lab dispatch to be denied without distinct trusted operator approval, before handler or evidence;
2. The policy boundary not to treat caller-supplied `is_lab=True` as risk-5 approval;
3. A forged `dataclasses.replace` run context not to mint independent approval provenance;
4. A switch to a different synthetic target asset under the same unapproved risk-5 run to remain denied;
5. A switch to a different registered risk-5 tool and capability under that run to remain denied;
6. An external documentation-only hostname to be rejected even when an untrusted caller marks its context `is_lab=True`; a flag is not physical isolation, environment attestation, or enforced egress control;
7. An unrelated generic `AuthorizationGrant` (fictional issuer, foreign tenant) not to substitute for a separate human lab approval;
8. Model-supplied tool arguments `operator_approved=True` and arbitrary `approval_reference` not to become approval provenance;
9. A backdated mutable-copy run context not to supply current operator approval.

Seven **ordinary positive controls** verify the already-existing risk-4 ceiling, lab-mode separation, immutable denial inputs, missing step-up/attestation fields, temporal metadata non-escalation, **a real no-op lower-risk lab dispatch with disposable SQLite evidence**, **and a direct source-RED witness** that rejects masked import/runtime/fixture failures. The witness calls each expected-RED body outside unittest's expected-failure harness and requires the precise expected missing-denial assertion. If RED cases report `expectedFailure`, that proves **the production gap is still open**. A green workflow running expected RED is never proof that the gap is fixed.

## Required integrated fix / closure

- Durable operator-only risk-5 approval and revocation, bound to exact run, client, engagement, asset, tool, capability, approval time, and independent operator identity, with no inference from a model, `is_lab`, or caller risk ceiling.
- Trusted environment-isolation attestation plus enforced egress isolation; mere loopback or a lab flag is not trusted proof.
- The mandatory step-up must guard **every raw and integrated risk-5 handler route**, including registry operations. No alternate executor may bypass it.
- Replace all nine expected REDs with ordinary passing deny-before-handler/evidence tests **on the integrated source**; verify positive approval and revocation controls without launching active handlers.
- Exact immutable-head Python 3.11/3.14 unit tests and genuine producer integrations, registered permanent VPS proof, independent security/privacy review, owner sign-off, customer consent as applicable, and explicit human release approval.

Run only offline via the repository's established CI. For isolated tests: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1173_raw_risk5_stepup_matrix_20261015.py' -v`.

**No merge, deployment, live target activation, external scanning, or fabricated approval.**
