# LightUp · Lab Scenario Studio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** [Assessment-runtime issue #1593](https://github.com/Zennay/Lightup/issues/1593). This is a local-only human scenario authoring workflow, **not** a scanner, run launcher, consent issuer, authorization-grant validator, target discovery system, retest engine or deployment feature.

## Delivered product

**Open `lab-design/standalone.html` in a browser** (download from the PR branch) to compose your own original isolated lab exercises. No installation, server, network, browser storage, credentials, HTTP clients, DNS, worker, action-time consent or scanner is required. A locally authored catalogue is handled in memory until you explicitly download a PRIVATE JSON file or close/Forget.

- **Order and safely copy** individual scenarios with explicit Up/Down and Copy-unscored actions. Copies preserve private numeric target context but deliberately reset all ground truth to *unscored* so old expected findings are never automatically carried into a supposedly new exercise. Clearing or replacing a nonempty workspace requires explicit confirmation.
- **Create/edit/delete** up to 32 independent scenarios, with unique canonical IDs, short human titles and descriptions, and up to 16 exact **numeric** lab-only IP targets per scenario.
- Accept only **127.0.0.0/8**, **10.0.0.0/8**, **172.16.0.0/12**, **192.168.0.0/16**, **::1**, IPv6 **fc00::/7** and **fe80::/10** literal addresses. Public, external, special-use documentation addresses, hostnames, URLs, ports, ambiguous IPv4 spellings, IPv4-mapped IPv6, zone IDs and CIDR notation are not allowed. These are strict planning boundaries, **not permissions**. In particular, do not treat "private" IPs as proof of authority.
- Model **unscored** ground truth (`null`) separately from **scored zero findings** (`[]`) or up to 64 explicit expected/planted findings. Each finding has exactly original LightUp `ExpectedFinding.identifier`, `title`, `capability_id` and severity `critical|high|medium|low|info`.
- **Append another PRIVATE catalog** after loading or creating 1–31 real local scenarios. Atomic, duplicate-ID and 32-scenario bound checking preserve the currently open editor and existing data on error. Fictional demo is deliberately not mixed into real-source append.
- **Private ground-truth capability map** groups manually declared finding capability IDs by severity and anonymous scenario slot. Displays unscored and explicitly zero-finding scenarios separately, so absent expected findings are not presented as verified coverage. Capability IDs are shown only in the private browser workspace and omitted from redacted public summaries.
- **Staged replacement before acceptance:** selecting an existing PRIVATE JSON does not overwrite the current editor. A numbered, private original scenario-ID delta view shows added, changed, unchanged and ABSENT (never "fixed") cases. Review and explicitly accept replacement, or discard it without losing prior work. Editing, deleting, appending, loading the demo or forgetting source data invalidates older staged comparisons.
- **Import existing PRIVATE JSON** with strict duplicate-key rejection (including Unicode-escaped aliases), UTF-8 validation, bounded sizes and atomic fail-closed schema/target/identity/authority checks. Invalid import does **not** replace already entered scenarios.
- Built-in **FICTIONAL no-network demo** supplies three invented scenarios and contrasts unknown, zero and planted findings. No live target or real proof is implied.
- **PRIVATE catalog export** preserves explicitly entered targets and finding identities for internal lab design. It is never a safe public handoff: handle it like sensitive material.
- **Standalone human handoff brief:** download a completely script-free, no-network HTML briefing with only numeric scenario, target and planted severity totals, fixed disclaimers and explicit false authority fields. The browser print layout is independently redacted: original capability IDs and staged source-diff scenario identities are excluded even when visible in the private editor. The fictional demo is labeled in all exported formats.
- **Aggregate redacted REVIEW_ONLY JSON** carries only scenario/target/IPv6 counts and expected-finding counts by severity. No original target IP, scenario/finding ID, name, description, title or capability name; four authority flags are literal false. Print only aggregate human review information.

## Native offline Python bridge

The distinct opt-in `lab-design/native_bridge.py` uses the original `src/lightup/labeval.py` dataclasses without modifying them. It validates the same catalog shape through Python's standard-library `ipaddress`, constructs the original **LabScenario** and **ExpectedFinding** objects **in memory** and prints only redacted counts. It imports **no LabEvaluationHarness**, starts no run, performs no target IO, and cannot verify real asset ownership or consent. Use from the repository root:

```bash
python3 lab-design/native_bridge.py lab-design/fictional-example.json
python3 lab-design/native_bridge.py /private/path/catalog.json --emit-python /private/path/my_lab_scenarios.py
```

### Compare two private catalog revisions without execution

The native offline bridge can compare two separately admitted catalogs and report only aggregate membership, changed target sets and changed ground-truth sets. Neither source IPs nor scenario IDs are printed. ABSENT is never a remediation claim.

Run from the repository root:

    python3 lab-design/native_bridge.py /private/baseline.json --compare /private/candidate.json
    python3 lab-design/native_bridge.py /private/baseline.json --compare /private/candidate.json --comparison-out /private/aggregate-review.json

The optional new report uses 0600 permissions and carries REVIEW_ONLY plus four literal-false authority fields. Existing files and symlinks are not overwritten.

The second command is explicitly optional. It creates an **owner-only 0600 PRIVATE constructor module**, refusing to overwrite an existing file or symlink. The generated module defines `load_lab_scenarios()` that returns original `LabScenario` dataclasses when a human explicitly calls it. Importing that module alone does not start an evaluation; it provides no targets, scans, approvals, grants or execution authority. Rejected input exits with code 3 and generic HOLD without echoing original source identifiers.

**Native handoff is only a constructor adapter**, not a supported `LabEvaluationHarness` session launcher, authorization pipeline, evidence verifier or CI gate. Original constructor admission is an additional narrowing gate. Public-network adapters and scans are intentionally outside this scope.

## Technical boundaries

Catalog v1 has *exactly* these top-level fields: `schema` = `lightup.lab_design_catalog.v1`, `status` = `DRAFT_ONLY`, four literal-false `authorized`, `consent_verified`, `dispatch_allowed` and `release_allowed`, and a bounded `scenarios` array. Each scenario has exactly `scenario_id`, `name`, `description`, `targets` and `expected_findings`. Each expected finding has exactly four original fields as described above. Zero or extra fields fail. The Python bridge uses exact built-in types for every source field.

The single-file artifact is generated deterministically from adjacent `index.html`, `style.css` and `app.js` using `python3 lab-design/build_standalone.py`. It includes a restrictive SHA-256-pinned Content-Security-Policy and needs no web access or remote fonts. The native bridge is a separate local Python file, **not embedded in the browser app**.

**Active worker isolation:** entirely new `lab-design/` paths only. Do not modify original `labeval.py`, `labrun.py`, `scope.py`, auth, targets, scanners, grants, CI, runners or active PR #1515 comparator, #1576 reviewdesk, #1585 trajectory or #1592 candidate matrix. No QA/regression/tests are written or run.

**Release boundary unchanged:** separately authenticated client and operator consent with action-time revocation, original security source-owner repairs #177/#182/#829, independent security/privacy, exact-HEAD complete original hosted plus permanently registered named VPS CI and explicit HUMAN GO are not established. **No merge, deploy, scans, grants, active handlers, retest, real targets or release.**
