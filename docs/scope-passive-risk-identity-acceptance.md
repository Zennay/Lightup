# PASSIVE_PUBLIC risk identity regression

The passive-only decision currently compares `requested_risk > RiskLevel.PASSIVE` without requiring `type(requested_risk) is RiskLevel`. Integers, booleans and foreign IntEnums with lower numeric values may be accepted as valid permission metadata.

Acceptance: a canonical `RiskLevel.PASSIVE` is allowed; `True`, `0`, `1`, `-1`, and a foreign IntEnum are denied. The test is expected RED until the policy source owner absorbs the explicit risk identity check. This branch contains only a new offline regression and this document, without touching active `execution_policy.py` ownership or dispatching any network or target operation.
