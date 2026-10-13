# LightUp evidence-remediation #1075 — bounded payload-hash reference

**Stage:** INCUBATE M3/M7, PLAN/LAB ONLY.  
**Dependency:** own [DRAFT PR #1267](https://github.com/Zennay/Lightup/pull/1267) exact immutable head `e604ae8b57c5785ce295597a7ac0d112dfef97b8`.  
**Owner:** separate opt-in files only; no modifications to `src/lightup/state.py`, original issuer, tenant/scope owners, active worker PRs or `main`.

## Material functionality

`src/lightup/evidence_payload_integrity_reference.py` provides **uninstalled**, opt-in, local `verify_scoped_evidence_payload_reference(...)`. The caller explicitly supplies **already-held bytes**; the helper never fetches payloads from the internet or a target, persists bytes, or exports evidence.

- Reject payloads that are not exact immutable builtin `bytes`, byte subclasses or above the **8 MiB** hard maximum, before any store lookup, permission callback or hashing. Accept zero-length bytes when the original real issuer recorded their SHA-256. Require exact integer maximum (1…8 MiB).
- Call the existing optional scoped ID reader from parent #1267, which requires **canonical lowercase UUID4 before any store access**, trusted-reference run and capability labels, exact-`True` injected current-scope check before and after read, matching persisted ID/run/capability. This remains only a **caller-injected checking interface**, *NOT a functioning authenticated grant service*.
- Check that the resulting real `EvidenceRecord.sha256` is **exact 64 lowercase ASCII hex characters**. Compute `hashlib.sha256(payload).hexdigest()` of the held bytes and use `hmac.compare_digest()` for comparison; malformed or mismatched hash denies with generic error without exposing bytes, digest or identifier.
- Make a **third** injected current-permission check after hashing, before record return, refusing grants revoked during potentially lengthy hashing. **This is not transactionally atomic with authorization revocation**.
- Never update SQLite, issue grants, run assessments, remediate or attest an actual retest.

## Evidence and limits

`tests/test_evidence_1075_payload_integrity_reference_20261013.py` adds **15 genuine disposable SQLite unittest methods**: standard producer SHA and three grant checks, empty bytes, bounded exact bytes/mutable and subclass admission, numeric budget bounds, full/over-size, mismatched payload without durable mutation, corrupt BLOB/case/Unicode digest, syntactically good but wrong stored digest, invalid ID prelookup, first/second/third injected permission refusal before hash/during return, sanitized checker hidden `__context__`, and unknown-UUID generic denial. All inputs synthetic; no customer records/targets.

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_1075_payload_integrity_reference_20261013
```

**SECURITY LIMIT:** A stored database SHA-256 is **not** a cryptographic signature, independent origin attestation, an authenticated tenant grant, trusted evidence issuer proof or unmodified snapshot guarantee. If an attacker can replace both bytes and stored digest, this check cannot establish authenticity. No default `StateStore.get_evidence` integration exists; four intentional expected-RED tests from earlier #1265 remain unresolved. Owner must design authenticated provenance, payload acquisition, tenant/capability/action-time grant and durable revocation, historical-ID policy, RED→normal green installed regression, latest-main compatibility, hosted Python 3.11/3.14 and **registered permanent VPS CI**, independent review and explicit human release approval.

**DRAFT/HOLD / NO MERGE / NO DEPLOY.** No actual client database, internet target, scanning, evidence collection, model disclosure, executed remediation/retest or production impact.
