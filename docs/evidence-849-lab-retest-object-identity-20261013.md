# #849 — fail closed before accepting polymorphic retest FindingRecord

**LightUp M3/M7 Incubate · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/NO DEPLOY**

## Source ownership and dependency

The independent acceptance branch starts from the immutable head of original scope/lab provenance source-owner [PR #184](https://github.com/Zennay/Lightup/pull/184): `bc7242d5171856f69f2ec68d7b3cf06d64bbb938`. This branch adds only `tests/test_lab_retest_object_identity_849.py` and this document. It must not change `src/lightup/labsync.py`, domain schema, scope, credentials, tests on the #848/#850 evidence-intake branches, or any active worker file.

The original `retest_finding()` implementation consults `finding.title` before comparing the incoming finding with the persisted immutable record. Since base `FindingRecord` is a frozen dataclass but subclasses are accepted, an untrusted subclass can spoof equality and return a different known baseline check title. The candidate may thus select an unrelated check ID for updating the canonical durable finding.

## Acceptance

Synthetic on-disk SQLite internal-lab finding, patched `http_baseline.observe` only (no loopback or external network call):
- **PASS:** original exact canonical `FindingRecord` invokes the mocked observation and persists the expected FIXED state.
- **PASS:** genuine non-lab finding remains refused by the previously established scope/provenance gate.
- **Intentionally expected RED:** custom equality/inequality spoofing subclass with another known title must fail before observation and leave the original durable retest row unchanged.
- **Intentionally expected RED:** polymorphic title-access trap must be rejected by class identity *before* even reading the attacker-controlled `title` attribute.
- **Intentionally expected RED:** same-valued subclass must still be rejected without observation or durable mutation.

Every negative test reopens the SQLite database independently, verifies unchanged finding metadata, and asserts zero mocked observe calls. No target interaction or real retest takes place.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_lab_retest_object_identity_849.py' -v
```

**Pre-fix expected:** 5 tests: 2 ordinary PASS / 3 intentional expected RED. The RED decorators are not security approval. Source owner #184 / its authorized successor must validate `type(finding) is FindingRecord` before inspecting user-controlled finding attributes, preserve canonical retest behavior, remove all three RED markers, and show five ordinary PASS. Exact-head hosted Python 3.11 and 3.14, permanent registered VPS exact-head CI, current-main merge analysis, independent security/privacy review and explicit human authorization remain required.

No customer records, scans, DNS, target, real baseline observation, external AI, grant, evidence collection, remediation, real retest, deployment, verdict or attack-path modification.
