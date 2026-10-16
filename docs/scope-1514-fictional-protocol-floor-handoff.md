# #1514 — Fictional review-protocol downgrade HOLD diagnostic

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**
This is an isolated, opt-in **fictional** protocol-format diagnostic. It is not a source producer, grant, client/operator identity verifier, signature checker, consent receipt, policy engine, runtime gate or release signal. It must never be wired into active execution or real asset authorization as-is.

## Contract

- review_protocol_floor(frames, expected_version, minimum_version) inspects an exact built-in tuple of 1–32 exact FictionalFrame objects.
- Versions are exact built-in integers 1–16. The caller supplies both expected and minimum: minimum_version <= expected_version. Every individual frame must be exactly the expected version; merely being above minimum is insufficient. No implicit downgrade or future-schema reinterpretation.
- Every frame has a contiguous sequence starting at 1 and the same strict fictional case-[a-z0-9]{1,24}.example.test ID. Mixing, omission, duplication, type subclasses, booleans, unknown versions, malformed data all produce generic HOLD.
- The opt-in CLI receives at most 4096 bytes of one canonical ASCII RFC JSON object, in exact field order, with expected_version, minimum_version, and frames. Frames have exact keys version, case_id, sequence in order. Duplicate or escaped keys, whitespace drift, NaN/Infinity, noncanonical numbers, unknown fields and trailing bytes are rejected.
- Exit code 2 + constant REVIEW_ONLY means fictional field consistency only. Exit code 3 + constant HOLD means a mismatch. Exit code 0 is never used.
- All returns contain authorized=False, consent_verified=False, dispatch_allowed=False, release_allowed=False. They are Python objects, not credentials. A caller can forge its own data and expected versions and even a Python result object. This is not real rollback prevention or provenance attestation.

## Reproduce offline

Run: PYTHONPATH=tools python -m unittest discover -s tests -p test_fictional_protocol_floor_1514.py -v

Opt-in synthetic positive case:

    printf '%s' '{"expected_version":3,"minimum_version":3,"frames":[{"version":3,"case_id":"case-alpha.example.test","sequence":1}]}' | python tools/fictional_protocol_floor_cli_1514.py

Expected output REVIEW_ONLY, exit status 2; not permission. Change the frame version to 2: output HOLD, status 3. No real destinations, tools, network calls, grants or scans occur.

## Integration and release boundaries

All changes are NEW, unwired files. No modifications to runtime, legacy ActivationGate, ScopePolicy, domain persistence, existing auth tests, other worker branches, runner configurations or activation/release. Distinct from #1503 packet-byte integrity, #1505 history continuity, #1507 consent-conflict diagnosis and #1511 LAB capability diagnosis.

Still required: genuine separately authenticated client and operator consent, exact scope/risk/capability proof, revocation at use, original source-owner fixes, independent privacy/security review, complete original hosted CI and registered named permanent vps-bb300bba tests on exact release SHA, explicit human GO. No merge, deployment, active handler, real scan or release solely on this diagnostic.
