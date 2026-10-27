# Detection capabilities

LightUp's product promise rests on actually *finding* things. This document
describes the detection capabilities added on top of the M1 skeleton and how
they are kept honest.

Everything here obeys the platform safety invariants: active workers run
**lab-only** behind the policy gate and an independent lab-target check;
the supply-chain capability is **analysis-only** and never touches a target.

## Capability workers

| Worker | Tool id | Capability | Interaction | What it finds |
| --- | --- | --- | --- | --- |
| HTTP header baseline | `lab-http-baseline` | `web-baseline` | lab-active | Missing defensive response headers |
| TLS baseline | `lab-tls-baseline` | `web-baseline` | lab-active | Protocol, cipher and chain-trust weaknesses |
| Service inventory | `lab-service-inventory` | `network-services` | lab-active | Which bounded TCP ports accept connections |
| **Web configuration hygiene** | `lab-web-exposure` | `web-baseline` | lab-active | Served dev/metadata paths, debug/stack-trace leakage, directory listing, weak session-cookie attributes, origin-reflecting CORS, advertised TRACE |
| **Supply-chain advisory scan** | `supply-chain-advisory-scan` | `supply-chain` | analysis-only | Pinned dependencies with known advisories (OSV) |

### Web configuration hygiene (`lab-web-exposure`)

Extends the header baseline to the configuration mistakes that most often lead
to real incidents. Every path-based check:

1. requires a **content signature** in the response body (not just a 200), and
2. is compared against a **calibration probe** to a random path, so catch-all
   ("soft-404") servers that answer 200 for everything produce **zero** false
   positives — the single most important property for a scanner people trust.

Evidence records *what matched*, never the sensitive content itself: dotenv
findings store variable names only and cookie values are discarded.

### Supply-chain advisory matching (`supply-chain-advisory-scan`)

Known-vulnerable components are the cheapest path for most attackers. LightUp
matches observed components against an advisory database in the open
[OSV schema](https://ossf.github.io/osv-schema/):

- **Offline and deterministic** — the database is loaded from local OSV exports
  the operator supplies; no network access, so it runs in analysis-only mode
  and in CI.
- **Computed severity** — CVSS v3.0/v3.1 base scores are calculated from the
  advisory vector, not guessed.
- **Exploitation context** — a CISA KEV-format catalog flags advisories known
  to be exploited in the wild; these dominate prioritization.
- **Honest limits** — version ordering is a well-tested PEP 440 / SemVer
  approximation; `GIT`-type ranges are skipped (they need commit graphs) and
  the match result says so.

Supported manifests: `requirements*.txt`, `Pipfile.lock`, `poetry.lock`,
`package-lock.json` (v1/v2/v3) and CycloneDX JSON SBOMs. Unpinned
requirements are reported as a coverage gap, never silently dropped.

Future Security use: `diff_dependency_risk(before, after, db)` returns a
pre-merge verdict (`pass` / `warn` / `block`) for a proposed dependency change,
blocking when the change *introduces* a critical/high or known-exploited
advisory.

## Prioritization and attack chains

Raw findings are not an answer. `lightup.prioritization.prioritize(findings)`:

- assigns each finding a deterministic **priority score** from severity,
  known-exploited status and asset exposure, producing a stable "fix first"
  ordering; and
- correlates known weakness combinations on the same asset into **attack
  chains** — e.g. source-control metadata plus an exposed environment file is a
  credential-disclosure chain worth more than either finding alone. Chains are
  conservative: every required finding must be present on one asset.

The planner-driven assessment result (`lightup lab-assess`) now carries a
`prioritization` block.

## Measured, not asserted: the detection benchmark

Trust comes from measurement. `lightup lab-benchmark` runs **every** planted
fixture profile (header + web-exposure), scores the engine against each
profile's hand-maintained ground truth, and reports per-profile and aggregate
precision, recall and F1.

```bash
PYTHONPATH=src python -m lightup.cli lab-benchmark --fail-under 1.0
```

Ground truth is maintained independently of the engine, so a perfect score
means the engine found exactly what was planted — no more, no less. The
benchmark is offline and loopback-only and runs in CI to catch detection
regressions.

Current fixtures and their planted ground truth:

| Profile | Worker | Planted findings |
| --- | --- | --- |
| `exposed` | header baseline | 5 (all header checks) |
| `partially-hardened` | header baseline | 3 |
| `hardened` | header baseline | 0 |
| `leaky-app` | web exposure | 8 |
| `web-hardened` | web exposure | 0 |
| `catch-all` | web exposure | 0 (soft-404 suppression) |
