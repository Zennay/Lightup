# Remediation retest evidence binding — offline reference

**Status:** Proposed contract, not a production implementation, trusted attestation, or closure authority. M7/ST5 plan/lab only.

A finding must **not** transition to resolved merely because a user, model, or worker supplies a `passed` string. The verifier must link a retest to the same exact tenant, finding, finding revision and prior evidence digest, with a *distinct* canonical digest for the new retest evidence. A positively verified retest is only a necessary precondition; it does not itself grant authority, close a finding, or prove a vulnerability was eliminated.

## Acceptance boundaries

- Reject mismatched tenant/finding/revision and boolean integer impostors.
- Require explicit immutable prior/retest SHA-256 content-reference strings (64 lowercase hex bytes); forbid reusing the original digest as retest proof.
- Deny failed or unknown outcomes, unknown method labels, truthy nonboolean verification, extra fields and subclass/duck containers.
- Preserve caller inputs. Positive result means only *reference-shape eligible*, not production proof.
- A production verifier must additionally resolve both digests against tenant-scoped immutable stored evidence, verify trusted provenance, authorization/scope/time, actual retest outcome and current finding state, enforce atomic one-way state transition, and record an audit receipt. This reference deliberately does **none** of those things.
- Never infer resolved status from AI output, caller-controlled `verified`, an offline test pass, or a digest-shaped string.

## Run offline

```sh
python -m unittest discover -s tests -p 'test_remediation_retest_proof_binding_reference.py' -v
```

The reference performs no DNS, sockets, file mutation, scanners, active assessment, target contact or deployment. It is isolated in tests/docs, leaving current production remediation/verification owners untouched. An owner should review the contract and integrate only after independent exact-head CI and permanent-VPS evidence.
