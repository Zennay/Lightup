# #1093 — independent opt-in destination role metadata preview

**INCUBATE M3/M7 — PLAN/LAB ONLY. DRAFT / HOLD / NO MERGE / NO DEPLOY.**

This additive, opt-in module addresses issue #1093 independently of the existing branch-only metadata reference. It binds a set of typed HOST, ENDPOINT, PORT and PORT_SET roles to an **exact registered ToolDefinition** and verifies the argument shape, role/kind pairings, ambiguous authorities, and registration snapshots. No other worker paths, production ToolExecutor, policy, registry or workflows are modified.

The preview always returns a frozen `status=hold` receipt with `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `release_approved=false`. It never dispatches a handler, resolves DNS, calls a policy or grant resolver, issues a grant, writes evidence, or contacts a target. The separate #1093 acceptance branch remains unchanged.

Real tool execution **must not** use this preview as approval. Actual source-owner integration still requires current trusted same-engagement/tenant grant, capability, risk, window, revocation, same-authorized-asset destination matching (including DNS and redirects), safe retries, target-scoped egress and pre-I/O revalidation. The optional shape review proves none of these. Optional module is not installed anywhere in the executable ingress.

Unit tests: `PYTHONPATH=src python -m unittest discover -s tests -v`. Require exact-head hosted Python 3.11/3.14 and independent registered permanent VPS Python 3.11/3.14 proofs, source/security/privacy review, latest-main composition and human release decision. CI green never grants execution authority. All test inputs are local/synthetic; no customer data, scanners, real targets, deployments or grant issuance.

## W2 drift hardening (independent follow-up)

After W1, four new adversarial synthetic cases were added: late destination-role mutation, destination-key mutation, registered definition interaction change, and full registry map replacement. The optional preview now pins all of these to its constructor snapshot and denies before issuing even a non-authorizing HOLD receipt. **29 test methods** are staged, but exact final GitHub head CI has not been run; no claim of full repository compatibility. Python reflection and concurrent race resistance are out of scope for this opt-in reference and remain production owner review requirements.

## W3 receipt authority sealing

A further fix makes the preview receipt's four authority flags and HOLD status `init=False` fixed defaults, so callers cannot construct `DestinationReview(..., permit_issued=True)`, `execution_enabled=True`, or `release_approved=True` using the normal constructor. A 30th ordinary test checks constructor rejection. This still is not an authorization decision; Python reflection/substitution outside the preview trust boundary and actual dispatch remain original source-owner concerns. No production activation or target I/O.


## W4 — lexical ambiguity, type-safety, and callback-free denial

The opt-in reviewer now refuses alternative numeric-host authorities (whole-number and `0x`-prefixed forms), duplicate HOST/PORT role declarations across different parameter names, and noncanonical mutable `ToolDefinition`/`ToolParameter` metadata. Exact `RiskLevel`, `ParamKind`, typed strings, bounded descriptions, and preserved captured schema and role/registry identities are required. A substituted parameter tuple is rejected *by identity before tuple equality*, preventing attacker-controlled `__eq__` callbacks from running through an untrusted schema element. This is an independently reproduced correctness bug in the optional reference, not evidence of exploitation of production ToolExecutor.

52 staged synthetic unit cases include opaque denial of mutated or polymorphic metadata, DNS/socket/subprocess/urlopen no-call assertions, bounded-host/URL pre-parse checks, both canonical IPv6 and localhost HOLD controls, and permanent false execution/grant/release fields. A local synthetic module replica test run passed 52/52 on Python 3.13; **not a full canonical-repository or GitHub Actions result**. The branch is deliberately not integrated with production registries, handlers, policies, target adapter, ingress or job queue; no execution authority is conveyed.

### Pending source-owner evidence

- Original #107 executor and #156 registry owners must define/consume trusted destination-role metadata and enforce exact live-authorized asset/destination identity, including egress/retries/redirects, before any I/O.
- Reconcile the independent earlier #1093 branch-only acceptance oracle; do not overwrite or merge that worker's work.
- Confirm a current exact-head repo checkout on Python 3.11 and 3.14, four hosted jobs and two permanent registered `[self-hosted,zcloud,vps]` jobs, matching SHA and logs. Branch-only local checks do not meet release requirements.
- Obtain independent source-owner/security/privacy review, latest-main composition and explicit human release authorization.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY. No grant, target, scanner, DNS/network, production service or workflow dispatch.**


## W5 — canonical endpoint text and Unicode ambiguity

The optional shape review now rejects non-ASCII endpoint input *before* `urllib.parse.urlsplit`, including invisible marks and malformed lone-surrogate URI path text, requiring percent-encoded path bytes instead of parser-specific Unicode normalization. This is a conservative plan/lab reference constraint, **not** a deployed Unicode-path behavior change. Two new tests check rejection and a valid percent-encoded Unicode path that still yields only a HOLD receipt. The local synthetic module-replica run now passes 54/54 on Python 3.13; it is not equivalent to exact-GitHub-code Python3.11/3.14 CI.

The earlier numeric-host, hostile-equality, duplicate-role and non-I/O regressions remain. Exact-head full repository tests, durable authorization, authorized destination binding, registered self-hosted VPS runner evidence and separate independent review are still missing. DRAFT/HOLD, no PR, merge or deploy.


## W6 — exact lexical URL identity admission (2026-10-14)

**Concrete fix:** `urlsplit()` normalizes scheme case and can discard empty query/fragment delimiters. In this independent *non-authorizing* preview, that creates a discrepancy between the originally supplied address and the interpreted address. The opt-in `_endpoint()` now requires an original lowercase `http://` or `https://` scheme, rejects any fragment marker (even an empty one) or trailing empty query delimiter, and requires a byte-for-byte `p.geturl() == original` round trip after parser admission. Legitimate canonical ASCII URI / percent-encoded paths still return only `HOLD`.

**Tests:** Four additional synthetic scenarios exercise mixed-case schemes, empty `#`, empty `?` and canonical explicit query positive controls; another two verify a deliberately rewritten parser return is denied and canonical HTTP/HTTPS/IPv6 endpoints remain HOLD. Together with earlier tests this branch now contains **60 ordinary synthetic test methods**. An independently maintained local Python 3.13 *replica* of this module and lightweight orchestration stubs completed `compileall` and **60/60** `unittest` methods, including new W6 checks. This is a **local synthetic regression signal only, not proof of exact GitHub-file execution, official hosted matrix, source-owner test integration, or permanent VPS**.

### Authority and threat-model limitation

This API accepts a tuple of `DestinationField` declarations provided by its calling code; the preview **cannot prove those declarations originated from a trusted, registered source**. In production this would require a registry-owner review and binding to a canonical registered definition before use. Neither this reviewer nor a valid URL shape establishes tenant consent, live authorization, matching `call.asset`, DNS/redirect/egress confinement, safe dispatch, or a release token. **Never use a HOLD receipt as a permit**. Current integration is intentionally absent; no live targets, scan, grant, deployment or workflow dispatch.

### Unmet acceptance

Source-owner #107/#156 and policy owner #100 must integrate and validate real authority, existing separate #1093 metadata acceptance branch must be reconciled without overwriting it; exact-head hosted Python 3.11 and 3.14, registered permanent VPS CI, independent security/privacy, latest-main compatibility and explicit human authorization remain required. Project remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY**.


## W7 — deterministic corpus and genuine existing lab-tool registration acceptance

**Additive coverage (no existing source changes):** A seeded synthetic corpus explicitly denies 1,800 malformed authority strings using mixed schemes, userinfo, numeric-host aliases, invalid ports, control characters and fragments; 240 canonical HTTP/HTTPS/IPv4/IPv6/hostname/port/path combinations must each return **HOLD with authority flags false**. The synthetic local Python 3.13 replica with lightweight class stubs executed its first **62 cases**, including both full corpora: **PASS 62/62** with `compileall`. The number of `unittest` methods is not the number of corpus cases.

**New real source integration tests staged only in GitHub:** Two additional methods (`test_63`, `test_64`) import the repository's genuine `lightup.workers.http_baseline`, `tls_baseline`, and `service_inventory` definitions, register them into fresh real `ToolRegistry` instances, then review their role and value shapes without invoking any handler. They enforce no DNS/socket/urlopen calls and check malformed URL, boolean TLS port, and unordered port-set refusal. Those two methods **have not been executed**, because the local sandbox contains only lightweight stubs and cannot download the complete GitHub checkout. They require genuine repo CI on the exact final head and must not be described as green.

This is **LAB_ACTIVE schema evidence only**. The presence of real registered lab workers does not create TARGET_ACTIVE destination metadata, authorized target binding, production safety, or release authority. Owner #107/#156 must implement registry-owned destination roles and runtime authorization with correct current grant, asset identity, risk, tenant, revocation and egress. Branch remains isolated and non-authorizing: no PR/merge/CI queue/deploy, no real targets/scans/handlers.


## W8 — built-in LAB metadata origin proof and canonical tool ID fix

**Source-verified integration bug caught and repaired:** The previous opt-in manifest accepted only underscore-style `ToolDefinition.tool_id` values, yet all three genuinely registered built-in lab workers use kebab-case IDs (`lab-http-baseline`, `lab-tls-baseline`, `lab-service-inventory`). A genuine-shape local smoke control initially returned `DestinationMetadataRefused` for `lab-http-baseline`; the module now separately validates tool IDs with strict bounded ASCII kebab-case and keeps argument-name validation on stricter underscore identifiers. This is a fix to the **optional preview compatibility**, not a production authorization repair.

**New optional `known_lab_destination_manifest(registry, definition)`:** pins metadata fields for precisely the three original Python built-in `ToolDefinition` object identities, checks actual current registration and LAB_ACTIVE mode, never accepts caller-provided role mappings and returns only an offline reviewer with `status=hold`, `permit_issued=false`, `execution_enabled=false`, `authorization_verified=false` and `release_approved=false`. Same-name cloned/fabricated/unregistered definitions cannot use this path. No actual ToolExecutor, worker handler, scans, DNS, sockets, model, grant, resolver or evidence writes.

**Tests:** Added explicit positive/negative canonical tool-ID cases and owner-identity/refusal tests for real workers. There are now **70 staged test methods**, including 1,800 deterministic malformed authority and 240 canonical positive cases. Local **replica** on Python 3.13 with built-in-shape stubs: `compileall` passed, and `unittest` **70/70 PASS**. This is genuine local execution of the replica but **not full repo Python3.11/3.14 or exact GitHub file test**: the actual worker-import test methods 63–68 and real registered definition behavior still need exact-head repository CI. The original metadata source owner and existing independent branch must review new role pinning before any composition.

**Security and release:** It proves only non-authorizing metadata shape for currently lab-only worker declarations. It does not establish external target authorization or trusted destination matching for future TARGET_ACTIVE calls. Production source-owner integration, security/privacy, actual registered VPS evidence, latest-main review and explicit human release remain prerequisites. Incubate M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.


## W9/W10 — prevent built-in worker authority-shape spoofing

To make the optional built-in LAB-only role-map factory more reviewable without introducing any dispatch path, it now refuses **any change to the canonical original built-in** `tool_id`, `capability_id`, `min_risk=LOW_IMPACT`, `interaction=LAB_ACTIVE`, the complete positional parameter-name set, and the specific original registered handler function identity. A fake same-name factory argument, rebound worker module `ToolDefinition` with extra `redirect_url` parameter, changed capability or risk, cloned object, unregistered declaration, or registered replacement handler is refused with a fixed opaque exception. Registry handler changes *after* constructing the preview are also refused before a HOLD receipt.

This closes the narrower failure mode where inspecting only the current module-global ToolDefinition reference could appear to endorse attacker-controlled tool schema drift. In this isolated checker these checks **never grant capability permission**. A Python process that can arbitrarily monkeypatch trusted module globals **before** import/capture can still defeat normal Python identity assumptions; production trusted registry ownership, immutable config, independent auth and review remain separate requirements. This opt-in factory remains intentionally unavailable to TARGET_ACTIVE callers or production ingress.

**New negative/positive tests:** source/type/parameter drift, original registered handler pinning, post-capture handler replacement and kebab-case ID acceptance. Current branch stages **75 offline test methods**. A local Python 3.13 **source-shaped replica** with stubbed worker modules completed `compileall` and **75/75 PASS**, including original 1,800 malformed authorities and 240 canonical URL shape controls. This is NOT proof of exact committed GitHub Python code, actual worker imports from canonical GitHub repo, hosted Python 3.11/3.14 or permanent VPS execution. Real test methods in GitHub remain unexecuted until source-owner/CI lane is available.

**Safety invariant:** every successful `DestinationReview` remains `status=hold` and has `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `release_approved=false`. No real I/O, token, consent, grant, scan, analysis of customer targets, merge or deploy. **INCUBATE M3/M7 PLAN/LAB ONLY.**


## W11–W13 — resilient lab-handler provenance and encoded URI identity (14 Oct 2026)

**Genuine source changes committed on this isolated, non-authorizing branch:**
- The prior `known_lab_destination_manifest` dynamically read built-in worker module globals at each call; changing `run_http_baseline` and registering the injected handler could therefore create a false provenance match. The new `_ORIGINAL_LAB_TOOLS` tuple captures all three built-in ToolDefinition and handler function objects **once when the optional module is imported**. Subsequent module-global substitutions are refused. Added 3 real-worker regression methods (76–78) for swapped handler/definition and unchanged anchored review.
- Endpoint lexing now refuses malformed percent triplets; encoded delimiters and dot-segments that could be decoded into different path/query shapes; control bytes; invalid, truncated, overlong or surrogate UTF-8 octet runs; Unicode format/invisible characters, combining marks, private-use characters, non-space separators and non-NFC escape runs. Percent-encoded *canonical visible* Unicode, emoji, Euro and ASCII space are allowed only as **HOLD**-producing shapes. Added 11 regression methods (79–89), with socket/DNS/urlopen no-call checks and explicit positive examples.
- All unchanged production owner code, workflows, main, executor and registry remain outside this branch. No existing grant, scope, consent, network, policy, handler or evidence object is invoked in the opt-in review.

**Limits:** Python module-import anchoring is not tamper-proof attestation and cannot protect against arbitrary pre-import monkeypatching or introspection changing the original function's `__code__`. This offline preview does not bind the endpoint to a live authorized asset or issue permission; its receipt retains `status=hold` and all four authority flags false.

**Verification status:** 89 `unittest` methods now *staged* in GitHub (including 1,800 malformed and 240 canonical deterministic cases), but the final exact SHA has not been executed on the genuine repository's Python3.11/3.14 CI. Earlier Python3.13 replica tests do not prove new commits pass. An actual GitHub Actions PR/worker run is deliberately not spawned because the existing issue #1093 explicitly reserves branch-only acceptance to avoid duplicated permanent VPS queues. Source-owner/security/privacy/latest-main/human release reviews and exact-head GitHub-hosted/permanent registered VPS remain required. **INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.**


## W14 — source-shape offline no-authority controls

Added independent tests against the **actual LightUp source classes** (staged for official CI) to ensure neither a successful nor a denied built-in LAB metadata preview invokes `ExecutionPolicy.decide`, `ToolExecutor.execute`, or `StateStore.add_evidence`. Network/DNS sockets are mocked to raise immediately; the only success state is still `HOLD` with all authority flags `False`. These tests do not execute real tools, grant resolvers, scanner adapters or customer targets.

**Current test suite:** 91 synthetic/offline methods in this branch, of which the new real-worker import/registration cases remain unexecuted in the canonical repo. **No claim that 91/91 passed**: previous local light-stub tests applied only to earlier heads and cannot substitute for exact final SHA Python 3.11/3.14 hosted and registered VPS results. No new pull request, CI queue or runner restart was initiated in compliance with issue #1093's branch-only/noncollision ownership.

The standalone opt-in preview is an exploratory contract, not a trusted TARGET_ACTIVE authorization boundary. Live authorization/destination/tenant/revocation and independent owner/security/privacy review remain mandatory. **INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.**


## W15 — runnable offline verification command, without creating CI work

New independent `scripts/verify_trusted_destination_manifest_1093.py` invokes **only** the fixed `test_trusted_destination_manifest_optin_1093.py` test file in an existing checked-out workspace. It insists on the **exact 91-method** expected suite, stops at the first failure, and rejects any external file path, target, network endpoint, authorization reference or caller-supplied command argument. During test execution, network sockets, DNS, URL opening and subprocess/process creation are patched to fail immediately. It uses no credentials or service connectors.

Usage from the genuine repository checkout (offline only):
`python scripts/verify_trusted_destination_manifest_1093.py`

The stable minimal JSON response always has `status=hold`, `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, and `release_approved=false`, even if `offline_regression_passed=true`. The exit code is 0 only when the expected count ran with zero failures/skips/expected failures; otherwise the checker refuses/fails. **A green script response is NOT exact-head GitHub CI evidence, permanent registered VPS proof, consent or release approval**. CI owner must independently pin branch SHA and runner ID, run the exact required Python3.11/3.14+real-producer integration workflows, and obtain human/security/owner release gates.

This script was **created and committed but not executed on the registered VPS**: no new Actions run, duplicate queue or PR was opened under issue #1093's branch-only instruction. No source owner code, main, other workers or real targets were modified.


## W16 — close offline verifier import-time I/O window

Follow-up defensive bug fix to the new script: the initial implementation enabled no-network/no-process guards only for `unittest` execution, leaving test module **discovery/import** outside those guards. A test module or dependency could initiate I/O during import, before the intended block. The checker now wraps both discovery/import **and** execution in the same patch set (DNS, raw socket, socket connection, URL opener, `subprocess.run`/`Popen`, and `os.system`), enforcing a stronger offline-only boundary. It still cannot attest that the checkout or registered runner is trusted, and creates no authorization. Run the source script from an existing permitted runner checkout only; do not treat a JSON HOLD receipt as a production release gate.
