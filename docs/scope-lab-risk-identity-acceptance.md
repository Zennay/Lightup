# LAB_ACTIVE risk identity acceptance

## Finding

On the inspected `main` source, `ExecutionPolicy.decide()` enters the `InteractionKind.LAB_ACTIVE` branch and permits requests solely when `is_lab` is truthy. It does not verify that `requested_risk` is a canonical `RiskLevel`. An invalid raw integer, boolean, foreign `IntEnum`, null or object is therefore allowed as though a real risk level were provided.

## Required behavior

- Accept a canonical `RiskLevel.LOW_IMPACT` on an explicit lab-only request, subject to existing lab restrictions.
- Deny canonical lab risk on `is_lab=False`.
- Deny every foreign risk identity, including numeric lookalikes, `True`, `False`, strings, null, and arbitrary objects, before granting lab permission.
- Keep this check distinct from constraints on `TARGET_ACTIVE` and `PASSIVE_PUBLIC`.
- A repair must not loosen lab segregation or permit non-lab target interaction.

## Reproduction / evidence

Run `python -m unittest discover -s tests -p 'test_scope_lab_risk_identity_acceptance.py' -v` on this branch. The canonical controls are intended GREEN; malformed risk cases are intentionally expected RED until the production policy owner implements exact risk identity validation.

## Collision boundary

Only this documentation and `tests/test_scope_lab_risk_identity_acceptance.py` belong to this sidecar. Production `src/lightup/execution_policy.py` remains owned by the active policy PR #100 and dependent branches. This branch makes no source, deployment, network or target-capable changes. Coordinate with that owner for integration and rerun the offline suite on the exact integration head.

## Safety

Pure in-process acceptance with synthetic identifiers; no network, DNS, scanning, tool execution, exploit, authorization expansion, or remediation.
